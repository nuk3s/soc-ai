"""The one outcome of a hunt, its plain title and the bell lines (dogfood 2026-10-06).

S1: a hunt that could not run or could not answer read "No threat observed"
on the hunt page, the list and the bell. Operator 3.1 and K3: a catalog title
and a lead title read as machine text. Operator 1.2: eight bell lines said the
same thing about eight catalog runs of one sweep.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.hunting.hunt_words import hunt_title, window_phrase
from soc_ai.hunting.outcome import outcome_headline, public_outcome
from soc_ai.main import create_app
from soc_ai.store import host_dossier as dossier_store
from soc_ai.store import hunts as hunt_svc
from soc_ai.store.models import Hunt

# The finding the catalog composer writes when a query raised.
_RUN_FAILURE: dict[str, Any] = {
    "title": "Directory replication by a non-machine account: could not run",
    "detail": (
        "The identity-4662-dcsync-nonmachine hunt spec failed against the grid. The result is "
        "unknown. The data source did not accept a connection during the precondition query."
    ),
    "severity": "medium",
    "category": "visibility_gap",
    "hosts": [],
    "citations": [],
}
_CATALOG_OBJECTIVE = (
    "[catalog] identity-4662-dcsync-nonmachine: Directory replication by a non-machine "
    "account (now-1440m → now)"
)
_NO_ANSWER_NARRATIVE = (
    "The hunt searched for traffic to 10.99.0.30. The answer cannot be confirmed or ruled "
    "out because the data for 10.99.0.30 is 34 days old. No other host was named."
)


# ── The outcome rule ──────────────────────────────────────────────────────


def test_a_run_whose_every_finding_failed_could_not_run() -> None:
    assert public_outcome("complete", [_RUN_FAILURE]) == "could_not_run"
    headline = outcome_headline("could_not_run", "complete", [_RUN_FAILURE])
    assert headline == "The grid did not accept a connection. Hunt again when the grid is healthy."


def test_a_stopped_hunt_could_not_run_and_names_its_stop() -> None:
    for status in ("error", "cancelled", "interrupted"):
        assert public_outcome(status, [{"title": "x", "category": "threat"}]) == "could_not_run"
    assert outcome_headline("could_not_run", "cancelled", []) == (
        "A cancel request stopped this hunt before it finished."
    )
    assert outcome_headline("could_not_run", "error", [], "The model gateway refused.") == (
        "The model gateway refused."
    )


def test_a_narrative_that_cannot_confirm_or_rule_out_has_no_answer() -> None:
    assert public_outcome("complete", [], _NO_ANSWER_NARRATIVE) == "no_answer"
    headline = outcome_headline("no_answer", "complete", [], _NO_ANSWER_NARRATIVE)
    # The headline names the gap in the narrative's words, then the grid limit.
    assert headline == (
        "The answer cannot be confirmed or ruled out because the data for 10.99.0.30 is 34 "
        "days old. The grid answers 30 days back."
    )


def test_a_clean_narrative_is_no_threat() -> None:
    """Negative controls: "ruled out" and a lone "could not rule out" are not a gap."""
    assert public_outcome("complete", [], "The hunt ruled out beaconing.") == "no_threat"
    assert (
        public_outcome("complete", [], "No threat. The hunt could not rule out a slow scan.")
        == "no_threat"
    )
    assert outcome_headline("no_threat", "complete", [], "anything") is None


def test_a_threat_outranks_a_failed_query_and_a_gap_sentence() -> None:
    threat = {"title": "beacon to 203.0.113.9", "category": "threat"}
    assert public_outcome("complete", [threat, _RUN_FAILURE]) == "threat_found"
    assert public_outcome("complete", [threat], _NO_ANSWER_NARRATIVE) == "threat_found"


def test_a_gap_beside_a_failed_query_has_no_answer() -> None:
    """Only a run whose EVERY finding failed could not run. A part ran."""
    gap = {"title": "No telemetry for dns", "category": "visibility_gap"}
    assert public_outcome("complete", [gap, _RUN_FAILURE]) == "no_answer"
    assert public_outcome("complete", [gap]) == "no_answer"
    headline = outcome_headline("no_answer", "complete", [gap])
    assert headline is not None and "No telemetry for dns" in headline
    assert public_outcome("running", []) == "running"


# ── The plain title ───────────────────────────────────────────────────────


def test_a_catalog_title_loses_its_prefix_and_its_date_math() -> None:
    assert hunt_title(_CATALOG_OBJECTIVE) == (
        "Directory replication by a non-machine account, last 24 h"
    )
    assert window_phrase("now-60m", "now") == "last 1 h"
    assert window_phrase("now-43200m", "now") == "last 30 days"
    assert window_phrase("now-90m", "now") == "last 90 min"
    # Negative control: an analyst can type the prefix shape. Text that does
    # not parse comes back as its first line.
    assert hunt_title("[catalog] look for odd things") == "[catalog] look for odd things"
    assert hunt_title("hunt for beaconing\nsecond line") == "hunt for beaconing"


def test_a_lead_title_names_the_lead_and_the_machine() -> None:
    objective = (
        "[lead 6] Investigate domainadmin, 10.1.10.11. The lead formed from a catalog "
        "analytic match.\nObservations:\n- a"
    )
    assert hunt_title(objective, names={"10.1.10.11": "SR-DC01"}) == (
        "Lead 6 hunt: domainadmin on SR-DC01"
    )
    # Negative control: an address the dossier cannot name stays an address.
    assert hunt_title(objective) == "Lead 6 hunt: domainadmin on 10.1.10.11"
    assert hunt_title("[lead 3] Investigate 10.1.2.3. The lead formed.") == "Lead 3 hunt: 10.1.2.3"


# ── The API and the bell ──────────────────────────────────────────────────


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as c:
            yield c


def _seed(
    client: TestClient,
    *,
    objective: str,
    report: dict[str, Any],
    kind: str = "chat",
    started_by: str = "admin",
    narrative: str = "",
    status: str = "complete",
    finished_at: datetime | None = None,
) -> str:
    async def go() -> str:
        async with client.app.state.db_sessionmaker() as db:
            hunt = await hunt_svc.create(db, objective=objective, started_by=started_by, kind=kind)
            await hunt_svc.finalize(
                db, hunt.id, status=status, narrative=narrative or None, report=report
            )
            if finished_at is not None:
                row = await db.get(Hunt, hunt.id)
                assert row is not None
                row.finished_at = finished_at
                await db.commit()
            return hunt.id

    return asyncio.run(go())


def _catalog_failure(client: TestClient, *, finished_at: datetime | None = None) -> str:
    return _seed(
        client,
        objective=_CATALOG_OBJECTIVE,
        report={"findings": [_RUN_FAILURE], "narrative": "x"},
        kind="triggered",
        started_by="hunt-catalog",
        narrative=(
            "Directory replication by a non-machine account: the run failed. The result is "
            "unknown. The data source did not accept a connection during the precondition query."
        ),
        finished_at=finished_at,
    )


def test_a_catalog_run_that_failed_reads_could_not_run_everywhere(client: TestClient) -> None:
    hunt_id = _catalog_failure(client)
    detail = client.get(f"/api/v1/hunts/{hunt_id}").json()
    assert detail["outcome"] == "could_not_run"
    assert detail["outcome_label"] == "Could not run"
    assert detail["title"] == "Directory replication by a non-machine account, last 24 h"
    assert detail["outcome_headline"].startswith("The grid did not accept a connection.")
    row = next(r for r in client.get("/api/v1/hunts").json() if r["id"] == hunt_id)
    assert (row["outcome"], row["title"], row["starter"]) == (
        "could_not_run",
        detail["title"],
        "catalog",
    )
    notices = {n["id"]: n for n in client.get("/api/v1/notifications").json()}
    notice = notices[f"hunt-done:{hunt_id}"]
    assert notice["title"] == (
        "Analytic could not run: Directory replication by a non-machine account, last 24 h. "
        "The grid did not accept a connection. Hunt again when the grid is healthy."
    )
    assert notice["tone"] == "warn"
    assert "no threat" not in notice["title"].lower()


def test_a_free_text_hunt_with_no_answer_is_not_clean(client: TestClient) -> None:
    hunt_id = _seed(
        client,
        objective="Look for traffic to 10.99.0.30 in the last 30 days",
        report={"findings": [], "confidence": 0.75},
        narrative=_NO_ANSWER_NARRATIVE,
    )
    detail = client.get(f"/api/v1/hunts/{hunt_id}").json()
    assert detail["outcome"] == "no_answer"
    assert "34 days old" in detail["outcome_headline"]
    notices = {n["id"]: n for n in client.get("/api/v1/notifications").json()}
    assert notices[f"hunt-done:{hunt_id}"]["title"] == (
        "Hunt finished: no answer. Look for traffic to 10.99.0.30 in the last 30 days"
    )
    # Negative control: a clean hunt reads no threat found.
    clean = _seed(client, objective="sweep for beacons", report={"findings": []}, narrative="ok")
    notices = {n["id"]: n for n in client.get("/api/v1/notifications").json()}
    assert notices[f"hunt-done:{clean}"]["title"] == (
        "Hunt finished: no threat found. sweep for beacons"
    )
    assert notices[f"hunt-done:{clean}"]["tone"] == "accent"


def test_an_errored_agent_hunt_reaches_the_bell(client: TestClient) -> None:
    hunt_id = _seed(
        client,
        objective="hunt for beaconing",
        report={},
        narrative="The hunt failed: the model gateway refused the connection.",
        status="error",
    )
    notices = {n["id"]: n for n in client.get("/api/v1/notifications").json()}
    assert notices[f"hunt-done:{hunt_id}"]["title"] == (
        "Hunt could not run: hunt for beaconing. "
        "The hunt failed: the model gateway refused the connection."
    )
    assert notices[f"hunt-done:{hunt_id}"]["tone"] == "warn"


def test_one_sweep_of_catalog_runs_folds_into_one_line(client: TestClient) -> None:
    now = datetime.now(UTC).replace(tzinfo=None)
    clean_report: dict[str, Any] = {"findings": []}
    sweep = [
        _seed(
            client,
            objective=f"[catalog] spec-{i}: Analytic {i} (now-1440m → now)",
            report=clean_report,
            kind="triggered",
            started_by="hunt-catalog",
            narrative="clean",
            finished_at=now - timedelta(minutes=i),
        )
        for i in range(3)
    ]
    # Negative controls: a threat from the same sweep keeps its own line, and
    # a run from an earlier sweep starts a new group.
    threat = _seed(
        client,
        objective="[catalog] spec-t: Threat analytic (now-1440m → now)",
        report={"findings": [{"title": "hit on 10.0.0.5", "category": "threat"}]},
        kind="triggered",
        started_by="hunt-catalog",
        finished_at=now - timedelta(minutes=1, seconds=30),
    )
    earlier = _seed(
        client,
        objective="[catalog] spec-e: Earlier analytic (now-1440m → now)",
        report=clean_report,
        kind="triggered",
        started_by="hunt-catalog",
        narrative="clean",
        finished_at=now - timedelta(hours=3),
    )
    notices = client.get("/api/v1/notifications").json()
    ids = [n["id"] for n in notices]
    # The three runs of one sweep read as one line, at the newest run's place.
    folded = [n for n in notices if n["id"].startswith("hunt-sweep:")]
    assert [n["title"] for n in folded] == ["3 catalog hunts finished: no threat found"]
    assert folded[0]["id"] == f"hunt-sweep:no_threat:{sweep[-1]}"
    assert not any(f"hunt-done:{hunt_id}" in ids for hunt_id in sweep)
    # The threat keeps its line, between the fold and the earlier sweep.
    assert ids.index(folded[0]["id"]) < ids.index(f"hunt-done:{threat}")
    assert ids.index(f"hunt-done:{threat}") < ids.index(f"hunt-done:{earlier}")
    assert not any("[catalog]" in n["title"] for n in notices)


def test_the_fold_keeps_the_runs_of_one_sweep_together(client: TestClient) -> None:
    now = datetime.now(UTC).replace(tzinfo=None)
    first = _catalog_failure(client, finished_at=now - timedelta(minutes=3))
    _catalog_failure(client, finished_at=now - timedelta(minutes=2))
    _catalog_failure(client, finished_at=now - timedelta(minutes=1))
    notices = client.get("/api/v1/notifications").json()
    folded = [n for n in notices if n["id"].startswith("hunt-sweep:")]
    assert len(folded) == 1
    assert folded[0]["id"] == f"hunt-sweep:could_not_run:{first}"
    assert folded[0]["title"] == (
        "3 analytics could not run. The grid did not accept a connection. "
        "Hunt again when the grid is healthy."
    )
    assert folded[0]["tone"] == "warn"
    assert folded[0]["href"] == "/hunts?kind=triggered"


def test_a_lead_hunt_title_reads_the_dossier_name(client: TestClient) -> None:
    async def seed_host() -> None:
        async with client.app.state.db_sessionmaker() as db:
            await dossier_store.upsert_host(db, "10.1.10.11")
            await dossier_store.set_override(db, "10.1.10.11", "hostname", "SR-DC01", actor="t")
            await db.commit()

    asyncio.run(seed_host())
    hunt_id = _seed(
        client,
        objective=(
            "[lead 6] Investigate domainadmin, 10.1.10.11. The lead formed from a catalog "
            "analytic match.\nObservations:\n- a write"
        ),
        report={"findings": [{"title": "attribute writes", "category": "observation"}]},
        kind="lead",
        narrative="The two events are attribute writes.",
    )
    detail = client.get(f"/api/v1/hunts/{hunt_id}").json()
    assert detail["title"] == "Lead 6 hunt: domainadmin on SR-DC01"
    row = next(r for r in client.get("/api/v1/hunts").json() if r["id"] == hunt_id)
    assert row["title"] == detail["title"]
