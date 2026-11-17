"""The "vs last run" comparison matches a finding on its subject, never on its words.

Prod, 2026-11-12, hunt 01M78GYGVKV84GA91CPWEW0QB9: the strip read "7 new, 0
persisting, 5 resolved" with "resolved" in green. Two of the five were the
active exploit of the day before. The model had worded the two titles in a new
way, and the comparison matched on the title. A green "resolved" on a true
positive that still runs is a false all-clear.

A finding matches a finding of the last run when the two name one host and
share a rule, a technique or a cited document. The third list is "not
reported this run", because that is all the comparison knows.
"""

from __future__ import annotations

import asyncio
import itertools
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.api.webui.routes_hunts import _compute_hunt_diff
from soc_ai.config import Settings
from soc_ai.hunting import finding_match
from soc_ai.main import create_app
from soc_ai.store import hunts as hunt_svc
from soc_ai.store.models import Hunt

_OBJECTIVE = "Hunt for malicious activity over the past 72 hours."
_TARGET = "192.0.2.164"
_SOURCE = "192.0.2.226"
_RULE = "ET EXPLOIT php2shell remote code execution attempt"


def _f(
    title: str,
    *,
    hosts: list[str] | None = None,
    citations: list[str] | None = None,
    category: str = "threat",
    severity: str = "high",
    **extra: Any,
) -> dict[str, Any]:
    return {
        "title": title,
        "detail": f"{title}. The detail.",
        "severity": severity,
        "category": category,
        "hosts": hosts if hosts is not None else [_SOURCE, _TARGET],
        "citations": citations if citations is not None else [],
        **extra,
    }


def _stored(*findings: dict[str, Any], rule: str | None = None) -> dict[str, Any]:
    """The documents a run stored: every citation of ``findings`` that starts with 'doc'."""
    rules = frozenset({rule.casefold()}) if rule else frozenset()
    return {
        c: finding_match.StoredDocument(key=c, rules=rules)
        for f in findings
        for c in f["citations"]
        if isinstance(c, str) and c.startswith("doc")
    }


def _diff(
    current: list[dict[str, Any]],
    previous: list[dict[str, Any]],
    *,
    current_documents: dict[str, Any] | None = None,
    previous_documents: dict[str, Any] | None = None,
    machines: dict[str, str] | None = None,
) -> Any:
    """The diff of two runs. By default each run stored every 'doc...' id it cites."""
    prev = Hunt(id="01PREVIOUSHUNT", objective=_OBJECTIVE, created_at=datetime(2026, 11, 11, 18))
    return _compute_hunt_diff(
        current,
        previous,
        prev,
        current_documents=_stored(*current) if current_documents is None else current_documents,
        previous_documents=_stored(*previous) if previous_documents is None else previous_documents,
        machines=machines,
    )


def _titles(entries: list[Any]) -> list[str]:
    return sorted(e.title for e in entries)


# ── the match rule ──────────────────────────────────────────────────────────


def test_a_reworded_finding_with_a_shared_document_persists() -> None:
    """The prod case: two titles for one exploit, and one document in both."""
    previous = [
        _f(
            "Internal host runs ongoing php2shell exploitation",
            citations=["docAAAAAAAAAAAAAAAA1", "docAAAAAAAAAAAAAAAA2"],
        ),
        _f("LFI succeeds and leaks /proc/self/maps", citations=["docBBBBBBBBBBBBBBBB1"]),
    ]
    current = [
        _f(
            "php2shell exploit attempts hit 192.0.2.164",
            citations=["docAAAAAAAAAAAAAAAA2", "docCCCCCCCCCCCCCCCC1"],
        ),
        _f(
            "LFI on 192.0.2.164 leaks /proc/self/maps with HTTP 200",
            citations=["docBBBBBBBBBBBBBBBB1"],
        ),
    ]

    diff = _diff(current, previous)

    assert _titles(diff.persisting) == [
        "LFI on 192.0.2.164 leaks /proc/self/maps with HTTP 200",
        "php2shell exploit attempts hit 192.0.2.164",
    ]
    assert diff.new == []
    assert diff.notReported == []


def test_a_shared_rule_citation_on_one_host_persists() -> None:
    previous = [_f("OGNL rule is a loose match", hosts=["192.0.2.53"], citations=["rule:2036224"])]
    current = [
        _f(
            "OGNL body alerts are device check-ins",
            hosts=["192.0.2.53", "192.0.2.54"],
            citations=["RULE:2036224", "docDDDDDDDDDDDDDDDD1"],
        )
    ]

    diff = _diff(current, previous)

    assert _titles(diff.persisting) == ["OGNL body alerts are device check-ins"]
    assert diff.new == [] and diff.notReported == []


def test_the_rule_of_a_stored_document_matches_across_runs() -> None:
    """Each run cites the alerts of its own day. The rule of the alerts is the same."""
    previous = [_f("Exploit attempts continue", citations=["docAAAAAAAAAAAAAAAA1"])]
    current = [_f("Internal host exploits the PHP app", citations=["docCCCCCCCCCCCCCCCC1"])]

    apart = _diff(current, previous)
    assert _titles(apart.new) == ["Internal host exploits the PHP app"]
    assert _titles(apart.notReported) == ["Exploit attempts continue"]

    joined = _diff(
        current,
        previous,
        current_documents=_stored(*current, rule=_RULE),
        previous_documents=_stored(*previous, rule=_RULE),
    )
    assert _titles(joined.persisting) == ["Internal host exploits the PHP app"]
    assert joined.new == [] and joined.notReported == []


def test_a_shared_technique_on_one_host_persists() -> None:
    previous = [_f("DCSync by 192.0.2.10", hosts=["192.0.2.10"], mitre_techniques=["T1003.006"])]
    current = [
        _f(
            "Replication request by 192.0.2.10",
            hosts=["192.0.2.10"],
            mitre_techniques=["t1003.006"],
        )
    ]

    diff = _diff(current, previous)

    assert len(diff.persisting) == 1
    assert diff.new == [] and diff.notReported == []


def test_a_finding_with_no_key_still_matches_on_its_title_and_hosts() -> None:
    """A finding that cites nothing has only its title. The older rule holds for it."""
    previous = [_f("No host telemetry on 192.0.2.164", hosts=[_TARGET], category="visibility_gap")]
    current = [_f("no host telemetry on 192.0.2.164.", hosts=[_TARGET], category="visibility_gap")]

    diff = _diff(current, previous)

    assert len(diff.persisting) == 1
    assert diff.new == [] and diff.notReported == []


# ── many to many, in any order ──────────────────────────────────────────────


def test_one_finding_that_merges_two_reports_both_again() -> None:
    """The last run split one exploit into two findings. This run reports one."""
    previous = [
        _f(
            "php2shell exploit from source one", hosts=[_TARGET], citations=["docAAAAAAAAAAAAAAAA1"]
        ),
        _f(
            "php2shell exploit from source two", hosts=[_TARGET], citations=["docAAAAAAAAAAAAAAAA2"]
        ),
    ]
    current = [
        _f(
            "php2shell campaign from two sources",
            hosts=[_TARGET],
            citations=["docAAAAAAAAAAAAAAAA1", "docAAAAAAAAAAAAAAAA2"],
        )
    ]

    diff = _diff(current, previous)

    assert len(diff.persisting) == 1
    assert diff.new == [] and diff.notReported == []


def test_the_diff_is_the_same_in_every_order_of_the_findings() -> None:
    """A greedy one to one pass gave 1 new and 1 not reported in one order only."""
    previous = [
        _f("P1 rule one", hosts=[_TARGET], citations=["rule:1000001"]),
        _f("P2 rule two", hosts=[_TARGET], citations=["rule:1000002"]),
        _f("P3 another host", hosts=["192.0.2.99"], citations=["rule:1000001"]),
    ]
    current = [
        _f("C1 both rules", hosts=[_TARGET], citations=["rule:1000001", "rule:1000002"]),
        _f("C2 rule one", hosts=[_TARGET], citations=["rule:1000001"]),
        _f("C3 a new rule", hosts=[_TARGET], citations=["rule:1000009"]),
    ]

    seen = set()
    for cur in itertools.permutations(current):
        for prev in itertools.permutations(previous):
            diff = _diff(list(cur), list(prev))
            seen.add(
                (
                    tuple(_titles(diff.new)),
                    tuple(_titles(diff.persisting)),
                    tuple(_titles(diff.notReported)),
                )
            )

    assert seen == {(("C3 a new rule",), ("C1 both rules", "C2 rule one"), ("P3 another host",))}


# ── one machine under two names ─────────────────────────────────────────────


def test_a_host_name_and_its_address_are_one_machine() -> None:
    previous = [_f("Exploit of the app", hosts=["web01"], citations=["rule:1000001"])]
    current = [_f("Exploit of the app continues", hosts=[_TARGET], citations=["rule:1000001"])]

    apart = _diff(current, previous)
    assert len(apart.new) == 1 and len(apart.notReported) == 1

    machines = {"web01": "machine:agent:web01", _TARGET: "machine:agent:web01"}
    joined = _diff(current, previous, machines=machines)
    assert _titles(joined.persisting) == ["Exploit of the app continues"]
    assert joined.new == [] and joined.notReported == []


# ── negative controls: what must still read as a change ─────────────────────


def test_another_rule_on_the_same_hosts_is_a_new_finding() -> None:
    """Same hosts and no shared rule, technique or document: two subjects."""
    previous = [_f("Exploit attempts continue", citations=["rule:2036224", "docAAAAAAAAAAAAAAAA1"])]
    current = [
        _f("SSH brute force from the source", citations=["rule:2001219", "docCCCCCCCCCCCCCCCC1"])
    ]

    diff = _diff(current, previous)

    assert _titles(diff.new) == ["SSH brute force from the source"]
    assert diff.persisting == []
    assert _titles(diff.notReported) == ["Exploit attempts continue"]


def test_the_same_rule_on_another_host_is_a_new_finding() -> None:
    previous = [
        _f("Exploit attempts on the app", hosts=["192.0.2.164"], citations=["rule:2036224"])
    ]
    current = [_f("Exploit attempts on the app", hosts=["192.0.2.99"], citations=["rule:2036224"])]

    diff = _diff(current, previous)

    assert len(diff.new) == 1 and diff.persisting == []
    assert len(diff.notReported) == 1


@pytest.mark.parametrize(
    "citation",
    ["t_query_events_oql", "t_host_dossier:192.0.2.164", "192.168.100.20", "192.168.100.77:445"],
)
def test_a_citation_that_is_no_stored_document_is_no_shared_evidence(citation: str) -> None:
    """The citation gate keeps a tool name and an address. Neither is a document."""
    previous = [_f("Nmap sweep of the app", hosts=[_TARGET], citations=[citation])]
    current = [_f("Web shell upload on the app", hosts=[_TARGET], citations=[citation])]

    diff = _diff(current, previous)

    assert _titles(diff.new) == ["Web shell upload on the app"]
    assert _titles(diff.notReported) == ["Nmap sweep of the app"]
    keys = finding_match.finding_keys(current[0], documents={})
    assert keys.documents == frozenset() and not keys.cites


def test_a_document_id_that_the_run_did_not_store_is_no_document() -> None:
    """The shape of an id is not enough. The run must hold the document."""
    previous = [_f("Exploit attempts continue", citations=["docAAAAAAAAAAAAAAAA1"])]
    current = [_f("Exploit of the PHP app", citations=["docAAAAAAAAAAAAAAAA1"])]

    diff = _diff(current, previous, current_documents={}, previous_documents={})

    assert len(diff.new) == 1 and len(diff.notReported) == 1


def test_a_finding_of_an_older_shape_does_not_break_the_diff() -> None:
    previous = [{"title": "Old finding"}, {"title": "Other", "hosts": None, "citations": None}]
    current = [{"title": "Old finding", "hosts": [], "citations": [None, 5, {"a": 1}]}]

    diff = _compute_hunt_diff(
        current, previous, Hunt(id="H", objective="o", created_at=datetime(2026, 1, 1))
    )

    assert _titles(diff.persisting) == ["Old finding"]
    assert _titles(diff.notReported) == ["Other"]


def test_finding_keys_read_structured_fields_only() -> None:
    keys = finding_match.finding_keys(
        _f(
            "php2shell on 192.0.2.164, rule 2036224, T1190",
            hosts=["192.0.2.164", "WEB-01"],
            citations=["rule:2036224", "docAAAAAAAAAAAAAAAA1", "t_host_dossier:192.0.2.164"],
        ),
        documents={
            "docAAAAAAAAAAAAAAAA1": finding_match.StoredDocument(
                key="docAAAAAAAAAAAAAAAA1", rules=frozenset({"et exploit php2shell"})
            )
        },
    )

    assert keys.entities == frozenset({"192.0.2.164", "web-01"})
    assert keys.documents == frozenset({"docAAAAAAAAAAAAAAAA1"})
    assert keys.rules == frozenset({"2036224", "et exploit php2shell"})
    # The title names a technique. A title is text, and the keys do not read text.
    assert keys.techniques == frozenset()


def test_the_api_keeps_the_old_field_name_for_one_release() -> None:
    """A browser tab on the older bundle reads diff.resolved."""
    previous = [_f("Periodic flows are NTP", hosts=["192.0.2.7"])]
    diff = _diff([], previous)

    assert _titles(diff.notReported) == ["Periodic flows are NTP"]
    assert diff.model_dump()["resolved"] == diff.model_dump()["notReported"]


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


def _alert_hit(doc_id: str, rule: str) -> dict[str, Any]:
    return {
        "_id": doc_id,
        "_source": {
            "@timestamp": "2026-11-12T15:04:38.000Z",
            "event": {"dataset": "suricata.alert", "kind": "alert"},
            "rule": {"name": rule, "uuid": "2036224"},
            "source": {"ip": _SOURCE},
            "destination": {"ip": _TARGET},
        },
    }


def _seed(
    client: TestClient, *, at: datetime, findings: list[dict[str, Any]], hits: list[dict[str, Any]]
) -> str:
    async def _go() -> str:
        maker = client.app.state.db_sessionmaker  # type: ignore[attr-defined]
        async with maker() as db:
            hunt = await hunt_svc.create(
                db, objective=_OBJECTIVE, started_by="scheduler", kind="scheduled"
            )
            row = await db.get(Hunt, hunt.id)
            assert row is not None
            row.created_at = at
            await db.commit()
            await hunt_svc.append_events(
                db,
                hunt.id,
                [
                    {"sequence": 1, "kind": "hunt_started", "payload": {"objective": _OBJECTIVE}},
                    {
                        "sequence": 2,
                        "kind": "tool_call",
                        "payload": {
                            "tool_name": "t_query_events_oql",
                            "args": {"query": "event.kind:alert"},
                            "tool_call_id": "c1",
                        },
                    },
                    {
                        "sequence": 3,
                        "kind": "tool_result",
                        "payload": {
                            "tool_name": "t_query_events_oql",
                            "tool_call_id": "c1",
                            "result": {"total": len(hits), "hits": hits},
                        },
                    },
                ],
            )
            await hunt_svc.finalize(
                db,
                hunt.id,
                status="complete",
                narrative="seeded",
                report={"findings": findings, "narrative": "seeded", "affected_hosts": []},
            )
            return hunt.id

    return asyncio.run(_go())


def test_the_page_matches_on_the_rule_of_the_stored_documents(client: TestClient) -> None:
    """End to end: each run cites its own alert, and both alerts are one rule."""
    now = datetime.now(UTC).replace(tzinfo=None)
    _seed(
        client,
        at=now - timedelta(days=1),
        findings=[
            _f(
                "Internal host runs ongoing php2shell exploitation",
                citations=["docAAAAAAAAAAAAAAAA1"],
            ),
            _f("Periodic flows are NTP", hosts=["192.0.2.7"], category="observation"),
        ],
        hits=[_alert_hit("docAAAAAAAAAAAAAAAA1", _RULE)],
    )
    current = _seed(
        client,
        at=now - timedelta(hours=1),
        findings=[
            _f("php2shell exploit attempts hit 192.0.2.164", citations=["docCCCCCCCCCCCCCCCC1"]),
            _f("New external destination", hosts=["192.0.2.8"], category="observation"),
        ],
        hits=[_alert_hit("docCCCCCCCCCCCCCCCC1", _RULE)],
    )

    diff = client.get(f"/api/v1/hunts/{current}").json()["diff"]

    assert [e["title"] for e in diff["persisting"]] == [
        "php2shell exploit attempts hit 192.0.2.164"
    ]
    assert [e["title"] for e in diff["new"]] == ["New external destination"]
    assert [e["title"] for e in diff["notReported"]] == ["Periodic flows are NTP"]
    # The older field name stays for one release, as an alias.
    assert diff["resolved"] == diff["notReported"]


def test_the_page_reads_a_host_name_and_its_address_as_one_machine(client: TestClient) -> None:
    """The Hosts data holds web01 at 192.0.2.164. Two runs name it two ways."""
    from soc_ai.store.models import HostDossier, HostMachine

    async def _machine() -> None:
        maker = client.app.state.db_sessionmaker  # type: ignore[attr-defined]
        async with maker() as db:
            machine = HostMachine(
                machine_key="agent:web01",
                name="web01",
                names_json=[{"value": "web01", "source": "agent"}],
                primary_ip=_TARGET,
                address_count=1,
            )
            db.add(machine)
            await db.flush()
            db.add(HostDossier(ip=_TARGET, host_key=_TARGET, machine_id=machine.id))
            await db.commit()

    asyncio.run(_machine())
    now = datetime.now(UTC).replace(tzinfo=None)
    _seed(
        client,
        at=now - timedelta(days=1),
        findings=[_f("Exploit of the app", hosts=["web01"], citations=["rule:1000001"])],
        hits=[],
    )
    current = _seed(
        client,
        at=now - timedelta(hours=1),
        findings=[_f("Exploit of the app continues", hosts=[_TARGET], citations=["rule:1000001"])],
        hits=[],
    )

    diff = client.get(f"/api/v1/hunts/{current}").json()["diff"]

    assert [e["title"] for e in diff["persisting"]] == ["Exploit of the app continues"]
    assert diff["new"] == [] and diff["notReported"] == []
