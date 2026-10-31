"""An explicit re-run of the investigation of a hunt finding.

``POST /hunts/{hunt_id}/findings/{ordinal}/investigate`` is idempotent. A
running or complete run of the finding answers, and so do the run that the
hunt links to the finding and a run of another hunt with the same subject.
A finished run therefore blocked every new run of its finding, and the
Request more info refusal sent the analyst back to this route.

The JSON body field ``rerun`` asks for a new run. A run of the finding that
still runs answers, so a press never starts a second run beside it. Any other
run stays as a record, and the new run goes through the same promotion path:
the same subject, the same synthetic-evaluation marker, the same observation
and no Security Onion write.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.hunting.findings import subject_fingerprint
from soc_ai.main import create_app
from soc_ai.so_client.elastic import ElasticClient, EsSearchResult
from soc_ai.store import hunts as hunt_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.models import Hunt, Investigation

_MGR = "soc_ai.webui.hunt_manager.get_manager"
_OBSERVE = "soc_ai.hunting.sources.observe_hunt_finding"
_DOC = "tel-doc-00000001"


def _app_client(settings: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app) as c:
            yield c


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    yield from _app_client(settings_kratos)


class _Recorder:
    """Stands in for the investigation manager.

    ``start`` writes a running row with the kwargs the route passed and keeps
    the kwargs. No task lands the row, so the new run stays running.
    """

    def __init__(self, maker: Any) -> None:
        self.maker = maker
        self.started: list[dict[str, Any]] = []

    async def start(self, _state: Any, **kw: Any) -> str:
        subject = kw.get("subject")
        async with self.maker() as db:
            inv = await inv_svc.create(
                db,
                alert_es_id=kw["alert_id"],
                started_by=kw["started_by"],
                rule_name=kw.get("rule_name"),
                kind=kw.get("kind", "suricata"),
                hunt_id=kw.get("hunt_id"),
                finding_ordinal=kw.get("finding_ordinal"),
                is_synth_eval=kw.get("is_synth_eval", False),
                subject=subject.as_record() if subject is not None else None,
            )
        self.started.append({**kw, "inv_id": inv.id})
        return inv.id


def _finding() -> dict[str, Any]:
    return {
        "title": "Beacon from a web server",
        "detail": "192.0.2.10 calls 198.51.100.7 on a fixed cadence.",
        "severity": "high",
        "category": "threat",
        "hosts": ["192.0.2.10"],
        "citations": [_DOC],
    }


async def _seed_hunt(
    maker: Any,
    *,
    plan: dict[str, dict[str, Any]] | None = None,
    is_synth_eval: bool = False,
    status: str = "complete",
) -> str:
    async with maker() as db:
        hunt = await hunt_svc.create(
            db, objective="hunt for beacons", started_by="admin", is_synth_eval=is_synth_eval
        )
        if status != "running":
            await hunt_svc.finalize(
                db,
                hunt.id,
                status=status,
                narrative="The hunt found a beacon.",
                report={"findings": [_finding()], "narrative": "The hunt found a beacon."},
                finding_plan=plan or {},
            )
        return hunt.id


async def _seed_run(
    maker: Any,
    *,
    hunt_id: str,
    ordinal: int = 0,
    status: str = "complete",
    verdict: str | None = "needs_more_info",
    is_synth_eval: bool = False,
    fingerprint: str | None = None,
) -> str:
    """A run of a finding, with the hunt subject that every finding run carries.

    ``fingerprint`` is the subject fingerprint of the run. A run of another
    hunt with the same fingerprint is reusable.
    """
    subject = {
        "type": "hunt",
        "hunt_id": hunt_id,
        "subject_fingerprint": fingerprint,
        "judges": "finding",
    }
    async with maker() as db:
        inv = await inv_svc.create(
            db,
            alert_es_id=_DOC,
            started_by="system:hunt",
            kind="hunt",
            hunt_id=hunt_id,
            finding_ordinal=ordinal,
            is_synth_eval=is_synth_eval,
            subject=subject,
        )
        if status != "running":
            await inv_svc.finalize(db, inv.id, status=status, verdict=verdict, confidence=0.5)
        return inv.id


async def _link(maker: Any, hunt_id: str, ordinal: int = 0) -> Any:
    async with maker() as db:
        row = await db.get(Hunt, hunt_id)
        assert row is not None
        return hunt_svc.finding_links(row).get(ordinal)


async def _row(maker: Any, inv_id: str) -> Investigation:
    async with maker() as db:
        inv = await db.get(Investigation, inv_id)
        assert inv is not None
        return inv


def _post(
    client: TestClient,
    hunt_id: str,
    recorder: _Recorder,
    body: dict[str, Any] | None = None,
    ordinal: int = 0,
) -> Any:
    hits = [{"_id": _DOC, "_source": {"event": {"dataset": "zeek.conn"}}}]
    with (
        patch(_MGR, return_value=recorder),
        patch.object(
            ElasticClient,
            "search",
            AsyncMock(return_value=EsSearchResult(total=1, took_ms=1, hits=hits)),
        ),
    ):
        url = f"/api/v1/hunts/{hunt_id}/findings/{ordinal}/investigate"
        return client.post(url, json=body) if body is not None else client.post(url)


def test_without_rerun_a_complete_run_of_the_finding_still_answers(client: TestClient) -> None:
    """Control. No body and ``rerun: false`` keep the idempotent answer."""
    maker = client.app.state.db_sessionmaker
    hunt_id = asyncio.run(_seed_hunt(maker))
    old = asyncio.run(_seed_run(maker, hunt_id=hunt_id))
    recorder = _Recorder(maker)

    for body in (None, {"rerun": False}, {}):
        resp = _post(client, hunt_id, recorder, body)
        assert resp.status_code == 200, resp.text
        assert resp.json() == {"investigation_id": old, "existing": True}
    assert recorder.started == []


def test_rerun_starts_a_new_run_over_a_complete_run_of_the_finding(client: TestClient) -> None:
    maker = client.app.state.db_sessionmaker

    async def seed() -> tuple[str, str]:
        hunt_id = await _seed_hunt(maker)
        old = await _seed_run(maker, hunt_id=hunt_id)
        async with maker() as db:
            await hunt_svc.set_finding_link(
                db,
                hunt_id,
                0,
                hunt_svc.LINK_ENDED,
                investigation_id=old,
                origin=hunt_svc.ORIGIN_OPENED,
            )
        return hunt_id, old

    hunt_id, old = asyncio.run(seed())
    recorder = _Recorder(maker)
    with patch(_OBSERVE, AsyncMock()) as observe:
        resp = _post(client, hunt_id, recorder, {"rerun": True})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "existing" not in body
    new = body["investigation_id"]
    assert new != old
    assert len(recorder.started) == 1
    started = recorder.started[0]
    # The same promotion path: a finding run of this hunt, judged as a
    # finding, with its subject fingerprint and no Security Onion write.
    assert (started["kind"], started["hunt_id"], started["finding_ordinal"]) == ("hunt", hunt_id, 0)
    assert started["focus_origin"] == "hunt_finding"
    assert started["allow_so_writes"] is False
    assert started["is_synth_eval"] is False
    assert started["subject"].subject_fingerprint == subject_fingerprint(_finding())
    assert started["subject"].promoted_finding is not None
    assert started["started_by"] != "system:hunt"
    # The analyst acted on the finding again, so the observation is written.
    observe.assert_awaited_once()
    assert observe.await_args.kwargs["hunt_id"] == hunt_id
    assert observe.await_args.kwargs["ordinal"] == 0

    # The old run stays as a record.
    old_row = asyncio.run(_row(maker, old))
    assert (old_row.status, old_row.verdict) == ("complete", "needs_more_info")
    # The hunt names the new run on the finding.
    link = asyncio.run(_link(maker, hunt_id))
    assert (link.investigation_id, link.state, link.origin) == (
        new,
        hunt_svc.LINK_INVESTIGATING,
        hunt_svc.ORIGIN_MANUAL,
    )
    # The newest run of the finding is the new one, so the next press without
    # rerun returns it.
    again = _post(client, hunt_id, recorder)
    assert again.json() == {"investigation_id": new, "existing": True}
    assert len(recorder.started) == 1


def test_rerun_starts_a_new_run_over_the_linked_run(client: TestClient) -> None:
    """The own run failed, and the hunt links the finding to a complete run of
    another hunt. Without rerun the linked run answers. With rerun the
    finding gets its own run."""
    maker = client.app.state.db_sessionmaker
    fingerprint = subject_fingerprint(_finding())

    async def seed() -> tuple[str, str, str]:
        hunt_id = await _seed_hunt(maker)
        failed = await _seed_run(maker, hunt_id=hunt_id, status="error", verdict=None)
        async with maker() as db:
            other = await hunt_svc.create(db, objective="other hunt", started_by="admin")
        linked = await _seed_run(
            maker, hunt_id=other.id, verdict="true_positive", fingerprint=fingerprint
        )
        async with maker() as db:
            await hunt_svc.set_finding_link(
                db,
                hunt_id,
                0,
                hunt_svc.LINK_ENDED,
                investigation_id=linked,
                origin=hunt_svc.ORIGIN_REUSED,
            )
        return hunt_id, failed, linked

    hunt_id, failed, linked = asyncio.run(seed())
    recorder = _Recorder(maker)

    control = _post(client, hunt_id, recorder)
    assert control.json() == {"investigation_id": linked, "existing": True}
    assert recorder.started == []

    resp = _post(client, hunt_id, recorder, {"rerun": True})
    assert resp.status_code == 200, resp.text
    new = resp.json()["investigation_id"]
    assert "existing" not in resp.json()
    assert new not in (failed, linked)
    assert len(recorder.started) == 1
    link = asyncio.run(_link(maker, hunt_id))
    assert (link.investigation_id, link.origin) == (new, hunt_svc.ORIGIN_MANUAL)
    linked_row = asyncio.run(_row(maker, linked))
    assert (linked_row.status, linked_row.verdict) == ("complete", "true_positive")


def test_rerun_starts_a_new_run_over_a_reusable_run_of_another_hunt(client: TestClient) -> None:
    """No run of the finding and no link. A complete run of another hunt with
    the same subject answers without rerun. With rerun it does not."""
    maker = client.app.state.db_sessionmaker
    fingerprint = subject_fingerprint(_finding())

    async def seed() -> tuple[str, str]:
        hunt_id = await _seed_hunt(maker)
        async with maker() as db:
            other = await hunt_svc.create(db, objective="other hunt", started_by="admin")
        reusable = await _seed_run(
            maker, hunt_id=other.id, verdict="false_positive", fingerprint=fingerprint
        )
        return hunt_id, reusable

    hunt_id, reusable = asyncio.run(seed())
    recorder = _Recorder(maker)

    control = _post(client, hunt_id, recorder)
    assert control.json() == {"investigation_id": reusable, "existing": True}
    assert recorder.started == []

    resp = _post(client, hunt_id, recorder, {"rerun": True})
    assert resp.status_code == 200, resp.text
    assert "existing" not in resp.json()
    assert resp.json()["investigation_id"] != reusable
    assert len(recorder.started) == 1
    assert recorder.started[0]["hunt_id"] == hunt_id
    # The hunt planned no investigation for this finding, so no entry is written.
    assert asyncio.run(_link(maker, hunt_id)) is None


def test_rerun_returns_a_running_run_of_the_finding(client: TestClient) -> None:
    maker = client.app.state.db_sessionmaker

    async def seed() -> tuple[str, str]:
        hunt_id = await _seed_hunt(maker)
        await _seed_run(maker, hunt_id=hunt_id)
        running = await _seed_run(maker, hunt_id=hunt_id, status="running")
        return hunt_id, running

    hunt_id, running = asyncio.run(seed())
    recorder = _Recorder(maker)
    resp = _post(client, hunt_id, recorder, {"rerun": True})
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"investigation_id": running, "existing": True}
    assert recorder.started == []


def test_rerun_returns_a_running_linked_run(client: TestClient) -> None:
    """The hunt links the finding to a run that still runs. A second run of
    the finding beside it is a duplicate, so the linked run answers."""
    maker = client.app.state.db_sessionmaker
    fingerprint = subject_fingerprint(_finding())

    async def seed() -> tuple[str, str]:
        hunt_id = await _seed_hunt(maker)
        await _seed_run(maker, hunt_id=hunt_id, status="error", verdict=None)
        async with maker() as db:
            other = await hunt_svc.create(db, objective="other hunt", started_by="admin")
        running = await _seed_run(
            maker, hunt_id=other.id, status="running", fingerprint=fingerprint
        )
        async with maker() as db:
            await hunt_svc.set_finding_link(
                db,
                hunt_id,
                0,
                hunt_svc.LINK_INVESTIGATING,
                investigation_id=running,
                origin=hunt_svc.ORIGIN_REUSED,
            )
        return hunt_id, running

    hunt_id, running = asyncio.run(seed())
    recorder = _Recorder(maker)
    resp = _post(client, hunt_id, recorder, {"rerun": True})
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"investigation_id": running, "existing": True}
    assert recorder.started == []


def test_rerun_of_a_synthetic_evaluation_finding_keeps_the_marker(client: TestClient) -> None:
    maker = client.app.state.db_sessionmaker

    async def seed() -> tuple[str, str]:
        hunt_id = await _seed_hunt(maker, is_synth_eval=True)
        old = await _seed_run(maker, hunt_id=hunt_id, is_synth_eval=True)
        return hunt_id, old

    hunt_id, old = asyncio.run(seed())
    recorder = _Recorder(maker)
    resp = _post(client, hunt_id, recorder, {"rerun": True})
    assert resp.status_code == 200, resp.text
    new = resp.json()["investigation_id"]
    assert new != old
    assert recorder.started[0]["is_synth_eval"] is True
    assert asyncio.run(_row(maker, new)).is_synth_eval is True


def test_rerun_keeps_the_guards_of_the_route(client: TestClient) -> None:
    maker = client.app.state.db_sessionmaker
    recorder = _Recorder(maker)

    unknown = _post(client, "01HUNTDOESNOTEXIST00000000000", recorder, {"rerun": True})
    assert unknown.status_code == 404
    assert unknown.json()["detail"]["reason"] == "not_found"

    hunt_id = asyncio.run(_seed_hunt(maker))
    past_end = _post(client, hunt_id, recorder, {"rerun": True}, ordinal=5)
    assert past_end.status_code == 404
    assert past_end.json()["detail"]["reason"] == "finding_not_found"

    running_hunt = asyncio.run(_seed_hunt(maker, status="running"))
    still_running = _post(client, running_hunt, recorder, {"rerun": True})
    assert still_running.status_code == 409
    assert still_running.json()["detail"]["reason"] == "still_running"
    assert recorder.started == []


def test_rerun_is_refused_in_demo_mode(settings_kratos: Settings) -> None:
    demo = settings_kratos.model_copy(
        update={"soc_ai_demo": True, "es_hosts": ["http://127.0.0.1:9200"]}
    )
    resp = None
    for c in _app_client(demo):
        resp = c.post("/api/v1/hunts/some-hunt-id/findings/0/investigate", json={"rerun": True})
    assert resp is not None
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "demo_mode"


# ── After a Re-run: the hunt counts, the old run, two presses at once ────────


async def _seed_ended_own_run(maker: Any) -> tuple[str, str]:
    """A complete hunt that planned for finding 0, and its ended own run."""
    hunt_id = await _seed_hunt(maker, plan={"0": hunt_svc.plan_entry(hunt_svc.LINK_QUEUED)})
    old = await _seed_run(maker, hunt_id=hunt_id)
    async with maker() as db:
        await hunt_svc.set_finding_link(
            db,
            hunt_id,
            0,
            hunt_svc.LINK_ENDED,
            investigation_id=old,
            origin=hunt_svc.ORIGIN_OPENED,
        )
    return hunt_id, old


async def _finalize(maker: Any, inv_id: str, verdict: str = "false_positive") -> None:
    async with maker() as db:
        await inv_svc.finalize(db, inv_id, status="complete", verdict=verdict, confidence=0.8)


def _hunt_counts(client: TestClient, hunt_id: str) -> tuple[int, int, int, int]:
    detail = client.get(f"/api/v1/hunts/{hunt_id}")
    assert detail.status_code == 200, detail.text
    rows = client.get("/api/v1/hunts")
    assert rows.status_code == 200, rows.text
    row = next(r for r in rows.json() if r["id"] == hunt_id)
    return (
        detail.json()["findingsInvestigated"],
        detail.json()["findingsTotal"],
        row["findingsInvestigated"],
        row["findingsTotal"],
    )


def test_a_rerun_that_ends_counts_the_finding_as_investigated(client: TestClient) -> None:
    """The route links the new run as investigating, and nothing moves a
    manual link to ended. The count of investigated findings reads the run
    the link names, so the hunt reads complete again when the new run ends."""
    maker = client.app.state.db_sessionmaker
    hunt_id, _old = asyncio.run(_seed_ended_own_run(maker))
    assert _hunt_counts(client, hunt_id) == (1, 1, 1, 1)

    recorder = _Recorder(maker)
    with patch(_OBSERVE, AsyncMock()):
        resp = _post(client, hunt_id, recorder, {"rerun": True})
    assert resp.status_code == 200, resp.text
    new = resp.json()["investigation_id"]

    # The new run runs, so the finding is under investigation.
    assert _hunt_counts(client, hunt_id) == (0, 1, 0, 1)

    asyncio.run(_finalize(maker, new))
    assert _hunt_counts(client, hunt_id) == (1, 1, 1, 1)
    # A later press without rerun returns the new run, and the count holds.
    again = _post(client, hunt_id, recorder)
    assert again.json() == {"investigation_id": new, "existing": True}
    assert _hunt_counts(client, hunt_id) == (1, 1, 1, 1)


def test_the_old_run_of_a_finding_names_the_run_that_replaced_it(client: TestClient) -> None:
    """A Re-run leaves the old run as a record. Its page names the new run,
    and an override on it is refused, the way an older run of an alert is."""
    maker = client.app.state.db_sessionmaker
    hunt_id, old = asyncio.run(_seed_ended_own_run(maker))
    recorder = _Recorder(maker)
    with patch(_OBSERVE, AsyncMock()):
        new = _post(client, hunt_id, recorder, {"rerun": True}).json()["investigation_id"]

    # The new run still runs. The old page names it already.
    running = client.get(f"/api/v1/investigations/{old}")
    assert running.status_code == 200, running.text
    assert running.json()["supersededBy"] == new
    assert running.json()["supersededRun"]["id"] == new

    asyncio.run(_finalize(maker, new, verdict="true_positive"))
    landed = client.get(f"/api/v1/investigations/{old}").json()
    assert landed["supersededBy"] == new
    assert landed["supersededRun"]["verdict"] == "true_positive"

    refused = client.post(
        f"/api/v1/investigations/{old}/override", json={"verdict": "false_positive"}
    )
    assert refused.status_code == 409, refused.text
    assert refused.json()["detail"]["reason"] == "superseded"
    assert refused.json()["detail"]["invId"] == new

    # NEGATIVE CONTROL: the new run stands, and it takes the override.
    assert client.get(f"/api/v1/investigations/{new}").json()["supersededBy"] is None
    ok = client.post(f"/api/v1/investigations/{new}/override", json={"verdict": "false_positive"})
    assert ok.status_code == 200, ok.text


def test_a_run_of_another_finding_or_hunt_replaces_nothing(client: TestClient) -> None:
    """NEGATIVE CONTROL. Only a newer run of the same finding of the same hunt
    replaces a run. A sibling finding makes another claim, and the run of
    another hunt that the hunt reused stays the run of its own hunt."""
    maker = client.app.state.db_sessionmaker
    fingerprint = subject_fingerprint(_finding())

    async def seed() -> tuple[str, str, str]:
        hunt_id = await _seed_hunt(maker, plan={"0": hunt_svc.plan_entry(hunt_svc.LINK_QUEUED)})
        async with maker() as db:
            other = await hunt_svc.create(db, objective="other hunt", started_by="admin")
        reused = await _seed_run(maker, hunt_id=other.id, fingerprint=fingerprint)
        sibling = await _seed_run(maker, hunt_id=hunt_id, ordinal=1)
        async with maker() as db:
            await hunt_svc.set_finding_link(
                db,
                hunt_id,
                0,
                hunt_svc.LINK_ENDED,
                investigation_id=reused,
                origin=hunt_svc.ORIGIN_REUSED,
            )
        return hunt_id, reused, sibling

    hunt_id, reused, sibling = asyncio.run(seed())
    recorder = _Recorder(maker)
    with patch(_OBSERVE, AsyncMock()):
        new = _post(client, hunt_id, recorder, {"rerun": True}).json()["investigation_id"]
    assert new not in (reused, sibling)
    assert client.get(f"/api/v1/investigations/{reused}").json()["supersededBy"] is None
    assert client.get(f"/api/v1/investigations/{sibling}").json()["supersededBy"] is None


def test_the_superseded_filter_holds_the_old_run_of_a_finding(client: TestClient) -> None:
    """The needs-you count and the bell filter on the SQL twin of the rule."""
    from sqlalchemy import select

    maker = client.app.state.db_sessionmaker

    async def go() -> tuple[set[str], str, str, str, str]:
        hunt_id = await _seed_hunt(maker)
        old = await _seed_run(maker, hunt_id=hunt_id, verdict="true_positive")
        failed_retry = await _seed_run(maker, hunt_id=hunt_id, status="error", verdict=None)
        new = await _seed_run(maker, hunt_id=hunt_id, verdict="true_positive")
        sibling = await _seed_run(maker, hunt_id=hunt_id, ordinal=1, verdict="true_positive")
        async with maker() as db:
            rows = await db.scalars(select(Investigation.id).where(inv_svc.superseded_sql()))
            return set(rows.all()), old, failed_retry, new, sibling

    held, old, failed_retry, new, sibling = asyncio.run(go())
    assert old in held
    assert failed_retry in held
    assert new not in held
    assert sibling not in held


def test_two_reruns_at_once_start_one_run(client: TestClient) -> None:
    """Two presses at once, from two tabs or an API client. The second one
    reads the run the first one started, so one run starts."""
    from concurrent.futures import ThreadPoolExecutor

    maker = client.app.state.db_sessionmaker
    hunt_id, old = asyncio.run(_seed_ended_own_run(maker))
    recorder = _Recorder(maker)
    hits = [{"_id": _DOC, "_source": {"event": {"dataset": "zeek.conn"}}}]

    async def slow_search(*_args: Any, **_kwargs: Any) -> EsSearchResult:
        await asyncio.sleep(0.3)
        return EsSearchResult(total=1, took_ms=1, hits=hits)

    url = f"/api/v1/hunts/{hunt_id}/findings/0/investigate"
    with (
        patch(_MGR, return_value=recorder),
        patch(_OBSERVE, AsyncMock()),
        patch.object(ElasticClient, "search", slow_search),
        ThreadPoolExecutor(max_workers=2) as pool,
    ):
        futures = [pool.submit(client.post, url, json={"rerun": True}) for _ in range(2)]
        responses = [f.result() for f in futures]

    assert [r.status_code for r in responses] == [200, 200], [r.text for r in responses]
    assert len(recorder.started) == 1
    new = recorder.started[0]["inv_id"]
    assert new != old
    assert {r.json()["investigation_id"] for r in responses} == {new}
    assert sorted("existing" in r.json() for r in responses) == [False, True]
    link = asyncio.run(_link(maker, hunt_id))
    assert link.investigation_id == new
