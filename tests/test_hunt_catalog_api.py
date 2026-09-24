"""GET /api/v1/hunt-catalog — every declarative spec, joined to its sweep trail.

Same idiom as ``test_quality_api.py``: a real ``create_app()`` under
TestClient with ES/auth stubbed at the boundary, rows seeded through the app's
own sessionmaker. The shape under test is the one the catalog page renders: a
spec that has NEVER been swept still appears (nulls and zeros, not absence),
the trail's facts land on the right spec, and the sweep settings ride along so
the page can say whether the numbers are expected to move.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.hunting.execute import Candidate, SpecRun
from soc_ai.hunting.spec import load_catalog
from soc_ai.main import create_app
from soc_ai.store import hunt_spec_sweeps as sweeps_svc

CATALOG = load_catalog(Path(__file__).resolve().parents[1] / "soc_ai/hunting/catalog")
DCSYNC = "identity-4662-dcsync-nonmachine"
DECOY = "decoy-opencanary-interaction"


def _client(settings: Settings) -> Iterator[TestClient]:
    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    yield from _client(settings_kratos)


def _candidate(spec_id: str, scope: str) -> Candidate:
    return Candidate(
        spec_id=spec_id,
        scope_key=scope,
        scope_kind="user",
        doc_count=1,
        sample_ids=("idA",),
        anchor_id="idA",
        anchor_index=".ds-a",
        first_seen=None,
        last_seen=None,
    )


def _seed(
    client: TestClient,
    *,
    spec_id: str,
    now: datetime,
    hunt_id: str | None = None,
    shadow: bool = False,
    **run_over: Any,
) -> None:
    """Write one sweep row through the store, exactly as the sweep does."""
    base: dict[str, Any] = {
        "spec_id": spec_id,
        "since": "now-1440m",
        "until": "now",
        "blind": False,
        "precondition_docs": 47,
        "matched_docs": 0,
    }
    base.update(run_over)

    async def _go() -> None:
        async with client.app.state.db_sessionmaker() as db:
            await sweeps_svc.record(
                db,
                spec_id=spec_id,
                run=SpecRun(**base),
                hunt_id=hunt_id,
                shadow=shadow,
                since="now-1440m",
                until="now",
                now=now,
            )

    asyncio.run(_go())


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None, microsecond=0)


def test_every_catalog_spec_appears_even_when_never_swept(client: TestClient) -> None:
    """Absence would read as 'not installed'. A spec that has never run is a
    fact the page must show, with nulls where the trail has nothing to say."""
    resp = client.get("/api/v1/hunt-catalog")
    assert resp.status_code == 200
    body = resp.json()
    assert [s["id"] for s in body["specs"]] == list(CATALOG)
    dcsync = next(s for s in body["specs"] if s["id"] == DCSYNC)
    assert dcsync == {
        "id": DCSYNC,
        "title": CATALOG[DCSYNC].title,
        "level": "critical",
        "scope_kind": "user",
        "attack": list(CATALOG[DCSYNC].attack),
        "evaluator": "match",
        "tier": "shipped",
        "status": "live",
        "coverage": None,
        "last_swept_at": None,
        "last_fired_at": None,
        "blind": False,
        "last_error": None,
        "sweeps_24h": 0,
        "fired_24h": 0,
        "fresh_24h": 0,
        "already_handled_24h": 0,
        "shadow_24h": 0,
        "undecided_docs": 0,
        "unattributed_docs": 0,
        "truncated_docs": 0,
    }
    assert body["last_sweep_at"] is None


def test_the_trail_lands_on_the_right_spec(client: TestClient) -> None:
    now = _now()
    fired_at = now - timedelta(hours=2)
    _seed(
        client,
        spec_id=DCSYNC,
        now=fired_at,
        hunt_id="01FIRED",
        candidates=[_candidate(DCSYNC, "localuser")],
    )
    _seed(client, spec_id=DCSYNC, now=now - timedelta(hours=1), gate_already_handled=1)
    _seed(client, spec_id=DECOY, now=now, blind=True, precondition_docs=0, hunt_id="01GAP")

    body = client.get("/api/v1/hunt-catalog").json()
    by_id = {s["id"]: s for s in body["specs"]}

    dcsync = by_id[DCSYNC]
    assert dcsync["last_swept_at"] == (now - timedelta(hours=1)).isoformat() + "Z"
    assert dcsync["last_fired_at"] == fired_at.isoformat() + "Z"
    assert dcsync["blind"] is False
    assert dcsync["last_error"] is None
    assert dcsync["sweeps_24h"] == 2
    assert dcsync["fired_24h"] == 1
    assert dcsync["fresh_24h"] == 1
    assert dcsync["already_handled_24h"] == 1

    decoy = by_id[DECOY]
    assert decoy["blind"] is True
    assert decoy["last_fired_at"] is None, "a visibility-gap hunt is not a firing"
    assert decoy["fired_24h"] == 0
    assert decoy["sweeps_24h"] == 1

    # The two identity specs that were never swept are still there, untouched.
    for spec_id in set(CATALOG) - {DCSYNC, DECOY}:
        assert by_id[spec_id]["last_swept_at"] is None
        assert by_id[spec_id]["sweeps_24h"] == 0

    assert body["last_sweep_at"] == now.isoformat() + "Z", "the newest row across the catalog"


def test_a_shadow_sweep_is_counted_so_fresh_without_fired_has_a_reason(
    client: TestClient,
) -> None:
    """Seen on a live range: one shadow row and one live row for the SAME
    condition read "fired 0 · fresh 2" on the panel, whose tooltip defined
    fresh as hits not seen before. The shadow seed leaves the fire-once budget
    unspent, so the live sweep counts the condition fresh again; that is by
    design, and the row has to be able to say so. ``shadow_24h`` counts the
    shadow rows in the window and nothing else."""
    now = _now()
    same = [_candidate(DCSYNC, "svc-backup")]
    _seed(client, spec_id=DCSYNC, now=now - timedelta(minutes=2), shadow=True, candidates=same)
    _seed(client, spec_id=DCSYNC, now=now - timedelta(minutes=1), hunt_id="01LIVE", candidates=same)

    body = client.get("/api/v1/hunt-catalog").json()
    by_id = {s["id"]: s for s in body["specs"]}
    dcsync = by_id[DCSYNC]
    assert dcsync["shadow_24h"] == 1, "the live row must not count as shadow"
    assert dcsync["sweeps_24h"] == 2
    assert dcsync["fresh_24h"] == 2, (
        "the same condition is fresh to the shadow sweep and the live one"
    )
    assert dcsync["fired_24h"] == 1
    assert by_id[DECOY]["shadow_24h"] == 0, "a never-swept spec reads zero, not absent"


def test_a_spec_discarding_documents_says_so_on_the_route(client: TestClient) -> None:
    """The sweep counts documents its exclusions could not be evaluated
    against, marks the run not clean, and reports it on the command line and in
    the notification. Until this field the one screen built to catch a spec
    gone dark could not read it: a spec discarding thousands of documents an
    hour rendered "fired 0 · fresh 0 · handled 0 · last swept 2m ago", which is
    also what a healthy quiet spec renders.

    The newest row's fact, like ``blind`` and ``last_error``: the counters are
    a 24h rate and a rate would keep the number on screen after the grid
    started carrying the field again."""
    now = _now()
    _seed(client, spec_id=DCSYNC, now=now - timedelta(minutes=2), undecided_docs=5240)

    body = client.get("/api/v1/hunt-catalog").json()
    by_id = {s["id"]: s for s in body["specs"]}
    assert by_id[DCSYNC]["undecided_docs"] == 5240
    assert by_id[DCSYNC]["fresh_24h"] == 0, "no counter on the row could carry it"
    # The negative control: a spec with nothing undecided reads zero, so the
    # marker this field drives cannot appear on a healthy row.
    assert by_id[DECOY]["undecided_docs"] == 0


def test_a_cleared_undecided_count_leaves_the_route(client: TestClient) -> None:
    """A later clean sweep clears it, the way a later clean sweep clears the
    error. A marker that outlives the condition is one operators learn to
    scroll past."""
    now = _now()
    _seed(client, spec_id=DCSYNC, now=now - timedelta(minutes=30), undecided_docs=5240)
    _seed(client, spec_id=DCSYNC, now=now - timedelta(minutes=1))

    body = client.get("/api/v1/hunt-catalog").json()
    dcsync = next(s for s in body["specs"] if s["id"] == DCSYNC)
    assert dcsync["undecided_docs"] == 0


def test_a_spec_that_grouped_nothing_it_matched_says_so_on_the_route(
    client: TestClient,
) -> None:
    """Undecided's sibling, and it renders the same row without this field.

    These documents matched the detection and grouped into no scope, so they
    are inside the sweep's ``matched_docs`` — which the route does not carry —
    and inside no candidate. Every counter that IS on the row comes from the
    candidate list, so a spec whose scope field is empty on every hit renders
    fired 0 · fresh 0 · handled 0 over documents it genuinely fired on.
    """
    now = _now()
    _seed(
        client,
        spec_id=DCSYNC,
        now=now - timedelta(minutes=2),
        matched_docs=12,
        unattributed_docs=12,
    )

    by_id = {s["id"]: s for s in client.get("/api/v1/hunt-catalog").json()["specs"]}
    assert by_id[DCSYNC]["unattributed_docs"] == 12
    assert by_id[DCSYNC]["fresh_24h"] == 0, "no counter on the row could carry it"
    assert by_id[DECOY]["unattributed_docs"] == 0, "the negative control for the marker"


def test_a_spec_whose_grouping_hit_the_ceiling_says_so_on_the_route(
    client: TestClient,
) -> None:
    """The only one of the three where the row does NOT read as zeros.

    The grid stopped returning scope buckets at the executor's ceiling and
    reported the remainder as a lump sum, so the row shows a real firing count
    that is smaller than the truth. An under-report is indistinguishable from a
    total, which is why the number has to be said rather than inferred.
    """
    now = _now()
    _seed(
        client,
        spec_id=DCSYNC,
        now=now - timedelta(minutes=2),
        hunt_id="01FIRED",
        matched_docs=500,
        candidates=[_candidate(DCSYNC, "svc-backup")],
        truncated_docs=460,
    )

    by_id = {s["id"]: s for s in client.get("/api/v1/hunt-catalog").json()["specs"]}
    assert by_id[DCSYNC]["truncated_docs"] == 460
    assert (by_id[DCSYNC]["fired_24h"], by_id[DCSYNC]["fresh_24h"]) == (1, 1), (
        "the row reads like a healthy firing spec, which is exactly the problem"
    )
    assert by_id[DECOY]["truncated_docs"] == 0, "the negative control for the marker"


def test_a_cleared_unattributed_or_truncated_count_leaves_the_route(
    client: TestClient,
) -> None:
    """Both are the newest row's fact, like the error and like undecided. A
    detection narrowed under the ceiling, or a dataset that started carrying
    the scope field, is not still losing documents."""
    now = _now()
    _seed(
        client,
        spec_id=DCSYNC,
        now=now - timedelta(minutes=30),
        matched_docs=500,
        unattributed_docs=12,
        truncated_docs=460,
    )
    _seed(client, spec_id=DCSYNC, now=now - timedelta(minutes=1))

    dcsync = next(
        s for s in client.get("/api/v1/hunt-catalog").json()["specs"] if s["id"] == DCSYNC
    )
    assert (dcsync["unattributed_docs"], dcsync["truncated_docs"]) == (0, 0)


def test_an_errored_spec_reports_its_error(client: TestClient) -> None:
    _seed(client, spec_id=DCSYNC, now=_now(), error="ConnectionError: grid down")
    body = client.get("/api/v1/hunt-catalog").json()
    dcsync = next(s for s in body["specs"] if s["id"] == DCSYNC)
    assert dcsync["last_error"] == "ConnectionError: grid down"
    assert dcsync["sweeps_24h"] == 1
    assert dcsync["fired_24h"] == 0


def test_timestamps_are_utc_with_a_z_suffix(client: TestClient) -> None:
    """Store timestamps are naive UTC; a naive ISO string parses as LOCAL time
    in a browser. The page gets an explicit offset, spelled ``Z``."""
    _seed(client, spec_id=DCSYNC, now=_now())
    body = client.get("/api/v1/hunt-catalog").json()
    dcsync = next(s for s in body["specs"] if s["id"] == DCSYNC)
    assert dcsync["last_swept_at"].endswith("Z")
    assert "+00:00" not in dcsync["last_swept_at"]
    assert body["last_sweep_at"].endswith("Z")
    assert datetime.fromisoformat(dcsync["last_swept_at"]).tzinfo is not None


def test_sweep_settings_ride_along(settings_kratos: Settings) -> None:
    """Off by default. The page needs to know whether zeros mean 'quiet' or
    'nobody is looking', and that is a setting, not a row."""
    for client in _client(settings_kratos):
        body = client.get("/api/v1/hunt-catalog").json()
        assert body["sweeps_enabled"] is False
        assert body["sweep_interval_minutes"] == 60
        assert body["sweep_window_minutes"] == 1440

    enabled = settings_kratos.model_copy(
        update={
            "hunt_spec_sweeps_enabled": True,
            "hunt_spec_sweep_interval_minutes": 15,
            "hunt_spec_sweep_window_minutes": 120,
        }
    )
    for client in _client(enabled):
        body = client.get("/api/v1/hunt-catalog").json()
        assert body["sweeps_enabled"] is True
        assert body["sweep_interval_minutes"] == 15
        assert body["sweep_window_minutes"] == 120


def test_the_window_reported_is_the_one_a_sweep_runs_with(settings_kratos: Settings) -> None:
    """The panel says "looks back 60m" from the setting as typed while the
    trail rows record the clamped 61 the sweep actually used. The page's fact
    is what a sweep covers, so the route reports the effective values: the
    interval after its floor and the window after the clamp."""
    clamped = settings_kratos.model_copy(
        update={
            "hunt_spec_sweep_interval_minutes": 60,
            "hunt_spec_sweep_window_minutes": 60,
        }
    )
    for client in _client(clamped):
        body = client.get("/api/v1/hunt-catalog").json()
        assert body["sweep_interval_minutes"] == 60
        assert body["sweep_window_minutes"] == 61, "the trail says 61; the panel must not say 60"

    # Below the floor by environment (the console will not accept it).
    floored = settings_kratos.model_copy(
        update={
            "hunt_spec_sweep_interval_minutes": 0,
            "hunt_spec_sweep_window_minutes": 3,
        }
    )
    for client in _client(floored):
        body = client.get("/api/v1/hunt-catalog").json()
        assert body["sweep_interval_minutes"] == 5
        assert body["sweep_window_minutes"] == 6


def test_the_settings_are_read_live(client: TestClient) -> None:
    """A config-console toggle applies without a restart, like the loop itself."""
    assert client.get("/api/v1/hunt-catalog").json()["sweeps_enabled"] is False
    client.app.state.settings = client.app.state.settings.model_copy(
        update={"hunt_spec_sweeps_enabled": True}
    )
    assert client.get("/api/v1/hunt-catalog").json()["sweeps_enabled"] is True


async def _analyst_session(client: TestClient) -> str:
    """Seed a non-admin user + session row directly; return the raw token."""
    from soc_ai.store import auth as auth_svc

    async with client.app.state.db_sessionmaker() as db:
        user = await auth_svc.create_user(db, "ana", "longpassword1", role="analyst")
        return await auth_svc.create_session(db, user, ttl_hours=24)


def test_an_analyst_can_read_it(settings_kratos: Settings) -> None:
    """A read model like the hunts list, not a posture read like the quality
    trend: whether the catalog is working is the analyst's question."""
    from soc_ai.store.auth import SESSION_COOKIE

    secured = settings_kratos.model_copy(update={"api_auth_required": True})
    for client in _client(secured):
        assert client.get("/api/v1/hunt-catalog").status_code == 401
        client.cookies.set(SESSION_COOKIE, asyncio.run(_analyst_session(client)))
        resp = client.get("/api/v1/hunt-catalog")
        assert resp.status_code == 200, resp.text
        assert [s["id"] for s in resp.json()["specs"]] == list(CATALOG)


def test_each_spec_reports_which_loop_runs_it(client: TestClient) -> None:
    """The page cannot tell a quiet spec from an unswept one without this.

    A `profile` spec is answered from stored behavioural baselines by
    `soc-ai priors`, not by the catalog sweep. Rendered with the same trail
    fields as a swept spec, twelve of them showed rows of zeros under a green
    "Sweeps on" and read as quiet.
    """
    body = client.get("/api/v1/hunt-catalog").json()
    by_id = {s["id"]: s for s in body["specs"]}
    assert by_id, "the catalog returned no specs"

    evaluators = {s["evaluator"] for s in body["specs"]}
    assert evaluators == {"match", "profile"}, evaluators
    assert by_id["identity-4769-rc4-service-ticket"]["evaluator"] == "match"
    assert by_id["prior-hypervisor-novel-served-port"]["evaluator"] == "profile"


def test_a_profile_spec_cannot_set_the_header_timestamp(client: TestClient) -> None:
    """Only the specs this loop sweeps may speak for it.

    Taking the max across every spec let four healthy ones mask nine the
    catalog sweep no longer touches -- "Sweeps on, last sweep 37m ago" in
    green over rows last swept 23 hours earlier.
    """
    now = _now()
    stale = now - timedelta(hours=23)

    # A profile spec swept recently, as they all were before the split...
    _seed(client, spec_id="prior-hypervisor-novel-served-port", now=now)
    # ...and a match spec whose trail is old.
    _seed(client, spec_id=DCSYNC, now=stale)

    body = client.get("/api/v1/hunt-catalog").json()
    assert body["last_sweep_at"] == stale.isoformat() + "Z", (
        "the header took its timestamp from a spec this loop does not sweep"
    )


def test_a_profile_spec_carries_the_prior_sweeps_coverage(client: TestClient) -> None:
    """The shadow log said "blind=285 · could not be scored against any
    entity" in one line while the panel showed a row of zeros. The log was
    more honest than the product. The trail the prior sweep now writes is what
    lets the panel say the same sentence."""
    import asyncio

    from soc_ai.hunting.prior_sweep import PriorSweep
    from soc_ai.hunting.priors import PriorResult
    from soc_ai.store import prior_spec_runs

    spec_id = "prior-hypervisor-novel-served-port"
    sweep = PriorSweep(
        results=tuple(  # noqa: RUF005
            PriorResult(
                spec_id=spec_id, entity_kind="host", entity_key=f"10.0.0.{n}", coverage="blind"
            )
            for n in range(1, 6)
        )
        + (
            PriorResult(
                spec_id=spec_id,
                entity_kind="host",
                entity_key="10.0.0.9",
                coverage="not_applicable",
            ),
        ),
        evaluated_specs=(spec_id, "prior-audit-policy-changed-on-dc"),
    )

    async def _seed() -> None:
        async with client.app.state.db_sessionmaker() as db:
            await prior_spec_runs.record_sweep(db, sweep)

    asyncio.run(_seed())
    by_id = {s["id"]: s for s in client.get("/api/v1/hunt-catalog").json()["specs"]}

    cov = by_id[spec_id]["coverage"]
    assert cov is not None
    assert cov["blind"] == 5 and cov["not_applicable"] == 1 and cov["measured"] == 0
    assert cov["shadow"] is True
    assert cov["last_run_at"] is not None

    # A spec the sweep considered but had nothing to score gets a row of zeros
    # -- a fact about the run -- rather than reading as never-run.
    zeros = by_id["prior-audit-policy-changed-on-dc"]["coverage"]
    assert zeros is not None and zeros["measured"] == 0 and zeros["blind"] == 0

    # A match spec has no prior coverage at all.
    assert by_id[DCSYNC]["coverage"] is None
