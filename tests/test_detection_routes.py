"""Tests for the draft-detection routes (1.3 slice 3, Task 5):
``POST /hunts/{hunt_id}/findings/{ordinal}/draft-detection`` and
``POST /investigations/{inv_id}/draft-detection``.

Both routes are export-only (no persistence, no SO write) and flag-gated on
``settings.sigma_authoring_enabled`` (default off). Uses the
``test_hunts_api.py`` client harness: a real ``create_app()`` + ``TestClient``
with a mocked ``AsyncElasticsearch`` and mocked SO auth.
``soc_ai.api.webui.routes_detection.draft_detection`` is patched to a canned
:class:`SigmaDraft` (no real LLM call); the would-have-fired dry run is
exercised for real, with ``soc_ai.detection.validators.query_events_oql``
patched (the same target ``test_detection_validators.py`` patches) so no real
grid call happens. Citation resolution (the grounding-evidence fetch) is
served by patching :meth:`ElasticClient.search` wholesale, the same pattern
``test_finding_promotion.py`` uses for ``_resolve_finding_anchor``.

Confirm-first doctrine (owner-approved, STRICT): both routes refuse to draft
unless the finding's promoted investigation completed ``true_positive`` —
the 409 ``not_confirmed_true_positive`` tests below pin that on the
hunt-finding route (unpromoted / running promotion / FP verdict) and the
investigation route (FP verdict).

The guard-wiring tests below close a confirmed egress leak: the routes used
to call ``draft_detection`` with no guard at all, so a finding's real
internal IPs/hostnames (``Hunt.report`` is desanitized before persistence)
would egress to a cloud analyst model even with
``settings.analyst_cloud_redaction=True``. ``soc_ai.api.webui.routes_detection._build_guard``
(re-exported from ``runbook_promotion``) is mocked so the guard-construction
tests stay deterministic and don't need seeded internal-identifier rows.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic_ai.exceptions import UnexpectedModelBehavior
from soc_ai.agent.egress_guard import EgressResidueError
from soc_ai.config import Settings
from soc_ai.detection.models import SigmaDraft
from soc_ai.main import create_app
from soc_ai.so_client.elastic import ElasticClient, EsSearchResult
from soc_ai.store import hunts as hunt_svc
from soc_ai.store.models import Investigation

_DRAFT_DETECTION = "soc_ai.api.webui.routes_detection.draft_detection"
_BUILD_GUARD = "soc_ai.api.webui.routes_detection._build_guard"
_QUERY_EVENTS_OQL = "soc_ai.detection.validators.query_events_oql"

# _ID_SHAPED (shared with promote_finding) requires >=12 chars — every
# citation meant to resolve on the grid must be at least that long.
_CITATION = "tel-doc-000000000001"

_FINDINGS = [
    {
        "title": "Zerologon NetrServerAuthenticate3 anomaly",
        "detail": "10.0.0.5 sent repeated NetrServerAuthenticate3 calls to the DC.",
        "severity": "critical",
        "category": "threat",
        "hosts": ["10.0.0.5"],
        "citations": [_CITATION],
    }
]

# What the grid says the cited event actually was — the OBSERVED field values
# the route must fold into the drafter's evidence, and whose @timestamp must
# anchor the dry-run window.
_CITED_DOC: dict[str, Any] = {
    "_id": _CITATION,
    "_source": {
        "@timestamp": "2026-07-04T12:00:00.000Z",
        "event": {"dataset": "zeek.dce_rpc"},
        "source": {"ip": "10.0.0.5"},
        "destination": {"ip": "10.0.0.9", "port": 135},
        "zeek": {"dce_rpc": {"operation": "NetrServerAuthenticate3"}},
    },
}


def _canned_draft(**overrides: object) -> SigmaDraft:
    fields: dict[str, object] = {
        "title": "Zerologon NetrServerAuthenticate3 anomaly",
        "sigma_yaml": (
            "title: Zerologon NetrServerAuthenticate3 anomaly\n"
            "logsource:\n"
            "  category: dce_rpc\n"
            "detection:\n"
            "  selection:\n"
            "    zeek.dce_rpc.operation: NetrServerAuthenticate3\n"
            "  condition: selection\n"
        ),
        "oql": "event.dataset:zeek.dce_rpc AND zeek.dce_rpc.operation:NetrServerAuthenticate3",
        "rationale": (
            "The finding's citations show repeated NetrServerAuthenticate3 calls from "
            "a single source host, the Zerologon authentication-bypass pattern."
        ),
    }
    fields.update(overrides)
    return SigmaDraft(**fields)  # type: ignore[arg-type]


def _es_result(total: int, hits: list[dict[str, object]] | None = None) -> EsSearchResult:
    return EsSearchResult(total=total, took_ms=3, hits=hits or [])


def _cited_docs_search(hits: list[dict[str, Any]] | None = None) -> Any:
    """Patch ElasticClient.search to serve the citation-resolution lookup.

    Defaults to resolving ``_CITATION`` to ``_CITED_DOC``. The dry run never
    reaches this — it goes through the separately-patched
    ``query_events_oql``.
    """
    resolved = [_CITED_DOC] if hits is None else hits
    return patch.object(
        ElasticClient,
        "search",
        AsyncMock(return_value=EsSearchResult(total=len(resolved), took_ms=1, hits=resolved)),
    )


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
    """Flag-off (default) client — for the 403 checks."""
    yield from _client(settings_kratos)


@pytest.fixture
def flagged_settings(settings_kratos: Settings) -> Settings:
    return settings_kratos.model_copy(update={"sigma_authoring_enabled": True})


@pytest.fixture
def flagged_client(flagged_settings: Settings) -> Iterator[TestClient]:
    """Flag-on client — for the happy-path/guard checks."""
    yield from _client(flagged_settings)


@pytest.fixture
def redacted_client(flagged_settings: Settings) -> Iterator[TestClient]:
    """Flag-on + ``analyst_cloud_redaction`` on — for the egress-guard checks."""
    yield from _client(flagged_settings.model_copy(update={"analyst_cloud_redaction": True}))


def _seed_hunt(
    client: TestClient, *, status: str = "complete", findings: list[dict[str, object]] | None = None
) -> str:
    async def _go() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            hunt = await hunt_svc.create(
                db, objective="hunt for lateral movement", started_by="admin"
            )
            await hunt_svc.finalize(
                db,
                hunt.id,
                status=status,
                narrative="one host authenticated abnormally",
                report={"findings": findings if findings is not None else _FINDINGS},
            )
            return hunt.id

    return asyncio.run(_go())


def _seed_investigation(
    client: TestClient,
    *,
    kind: str = "hunt",
    status: str = "complete",
    verdict: str | None = "true_positive",
    hunt_id: str | None,
    finding_ordinal: int | None = 0,
) -> str:
    async def _go() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            inv = Investigation(
                id="01TESTDETECTROUTE0000000001",
                alert_es_id=_CITATION,
                kind=kind,
                status=status,
                verdict=verdict,
                hunt_id=hunt_id,
                finding_ordinal=finding_ordinal,
            )
            db.add(inv)
            await db.commit()
            return inv.id

    return asyncio.run(_go())


def _seed_confirmed_hunt(
    client: TestClient, *, findings: list[dict[str, object]] | None = None
) -> str:
    """A complete hunt whose finding 0 was promoted and confirmed
    true_positive — the only state the confirm-first doctrine drafts from."""
    hunt_id = _seed_hunt(client, findings=findings)
    _seed_investigation(client, hunt_id=hunt_id, finding_ordinal=0)
    return hunt_id


# ── Flag gate ────────────────────────────────────────────────────────────────


def test_hunt_finding_route_403_when_flag_off(client: TestClient) -> None:
    resp = client.post("/api/v1/hunts/nope/findings/0/draft-detection")
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "sigma_authoring_disabled"


def test_investigation_route_403_when_flag_off(client: TestClient) -> None:
    resp = client.post("/api/v1/investigations/nope/draft-detection")
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "sigma_authoring_disabled"


# ── Hunt-finding route ───────────────────────────────────────────────────────


def test_hunt_finding_route_happy_path(flagged_client: TestClient) -> None:
    hunt_id = _seed_confirmed_hunt(flagged_client)
    mock_query = AsyncMock(return_value=_es_result(4, hits=[{"_id": "hit-1"}]))
    with (
        patch(_DRAFT_DETECTION, AsyncMock(return_value=_canned_draft())),
        _cited_docs_search(),
        patch(_QUERY_EVENTS_OQL, mock_query),
    ):
        resp = flagged_client.post(f"/api/v1/hunts/{hunt_id}/findings/0/draft-detection")
    assert resp.status_code == 200
    body = resp.json()
    assert body["title"] == "Zerologon NetrServerAuthenticate3 anomaly"
    assert body["schema_ok"] is True
    dry_run = body["dry_run"]
    assert dry_run is not None
    assert dry_run["ran"] is True
    assert dry_run["hit_count"] == 4


def test_hunt_finding_route_unknown_hunt_404(flagged_client: TestClient) -> None:
    with patch(_DRAFT_DETECTION, AsyncMock(return_value=_canned_draft())):
        resp = flagged_client.post("/api/v1/hunts/does-not-exist/findings/0/draft-detection")
    assert resp.status_code == 404
    assert resp.json()["detail"]["reason"] == "not_found"


def test_hunt_finding_route_ordinal_out_of_range_404(flagged_client: TestClient) -> None:
    hunt_id = _seed_hunt(flagged_client)
    with patch(_DRAFT_DETECTION, AsyncMock(return_value=_canned_draft())):
        resp = flagged_client.post(f"/api/v1/hunts/{hunt_id}/findings/9/draft-detection")
    assert resp.status_code == 404
    assert resp.json()["detail"]["reason"] == "finding_not_found"


def test_hunt_finding_route_running_hunt_409(flagged_client: TestClient) -> None:
    hunt_id = _seed_hunt(flagged_client, status="running")
    with patch(_DRAFT_DETECTION, AsyncMock(return_value=_canned_draft())):
        resp = flagged_client.post(f"/api/v1/hunts/{hunt_id}/findings/0/draft-detection")
    assert resp.status_code == 409
    assert resp.json()["detail"]["reason"] == "still_running"


# ── Confirm-first doctrine (hunt-finding route) ──────────────────────────────


def test_hunt_finding_route_409_when_never_promoted(flagged_client: TestClient) -> None:
    """No investigation exists for this finding at all — drafting is refused
    until the analyst promotes it and lands a true-positive verdict."""
    hunt_id = _seed_hunt(flagged_client)
    with patch(_DRAFT_DETECTION, AsyncMock(return_value=_canned_draft())):
        resp = flagged_client.post(f"/api/v1/hunts/{hunt_id}/findings/0/draft-detection")
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["reason"] == "not_confirmed_true_positive"
    assert "true positive" in detail["hint"]


def test_hunt_finding_route_409_when_promotion_still_running(flagged_client: TestClient) -> None:
    hunt_id = _seed_hunt(flagged_client)
    _seed_investigation(
        flagged_client, hunt_id=hunt_id, finding_ordinal=0, status="running", verdict=None
    )
    with patch(_DRAFT_DETECTION, AsyncMock(return_value=_canned_draft())):
        resp = flagged_client.post(f"/api/v1/hunts/{hunt_id}/findings/0/draft-detection")
    assert resp.status_code == 409
    assert resp.json()["detail"]["reason"] == "not_confirmed_true_positive"


def test_hunt_finding_route_409_when_verdict_false_positive(flagged_client: TestClient) -> None:
    hunt_id = _seed_hunt(flagged_client)
    _seed_investigation(
        flagged_client, hunt_id=hunt_id, finding_ordinal=0, verdict="false_positive"
    )
    with patch(_DRAFT_DETECTION, AsyncMock(return_value=_canned_draft())):
        resp = flagged_client.post(f"/api/v1/hunts/{hunt_id}/findings/0/draft-detection")
    assert resp.status_code == 409
    assert resp.json()["detail"]["reason"] == "not_confirmed_true_positive"


# ── Grounding: citations resolved to real docs ───────────────────────────────


def test_hunt_finding_route_evidence_carries_observed_field_values(
    flagged_client: TestClient,
) -> None:
    """The drafter has no tools — the route must read the cited docs off the
    grid and fold their real field values into the evidence string, so the
    rule keys on observed values instead of hallucinated ones."""
    hunt_id = _seed_confirmed_hunt(flagged_client)
    mock_draft = AsyncMock(return_value=_canned_draft())
    with (
        patch(_DRAFT_DETECTION, mock_draft),
        _cited_docs_search(),
        patch(_QUERY_EVENTS_OQL, AsyncMock(return_value=_es_result(0))),
    ):
        resp = flagged_client.post(f"/api/v1/hunts/{hunt_id}/findings/0/draft-detection")
    assert resp.status_code == 200
    assert mock_draft.await_args is not None
    evidence = mock_draft.await_args.kwargs["evidence"]
    assert "event.dataset=zeek.dce_rpc" in evidence
    assert "zeek.dce_rpc.operation=NetrServerAuthenticate3" in evidence
    assert "source.ip=10.0.0.5" in evidence
    assert "destination.port=135" in evidence
    assert _CITATION in evidence


def test_hunt_finding_route_422_when_no_citation_resolves(flagged_client: TestClient) -> None:
    """Even a confirmed finding cannot draft from thin air: when none of its
    citations resolve on the grid there is nothing observed to key on."""
    hunt_id = _seed_confirmed_hunt(flagged_client)
    with (
        patch(_DRAFT_DETECTION, AsyncMock(return_value=_canned_draft())),
        _cited_docs_search(hits=[]),
    ):
        resp = flagged_client.post(f"/api/v1/hunts/{hunt_id}/findings/0/draft-detection")
    assert resp.status_code == 422
    assert resp.json()["detail"]["reason"] == "no_promotable_evidence"


def test_hunt_finding_route_422_when_no_id_shaped_citations(flagged_client: TestClient) -> None:
    """Prose-only citations never reach the grid lookup — same 422."""
    findings: list[dict[str, object]] = [{**_FINDINGS[0], "citations": ["short", "also prose"]}]
    hunt_id = _seed_confirmed_hunt(flagged_client, findings=findings)
    search = AsyncMock()
    with (
        patch(_DRAFT_DETECTION, AsyncMock(return_value=_canned_draft())),
        patch.object(ElasticClient, "search", search),
    ):
        resp = flagged_client.post(f"/api/v1/hunts/{hunt_id}/findings/0/draft-detection")
    assert resp.status_code == 422
    assert resp.json()["detail"]["reason"] == "no_promotable_evidence"
    search.assert_not_awaited()


def test_hunt_finding_route_citation_fetch_bounded_and_list_elided(
    flagged_client: TestClient,
) -> None:
    """A citation-heavy finding must not turn drafting into a bulk fetch:
    only the first few ids are resolved (full ``_source`` for ~5 docs is
    fine), and the evidence lists at most 20 ids with an elision suffix."""
    citations = [f"tel-doc-{i:012d}" for i in range(25)]
    findings: list[dict[str, object]] = [{**_FINDINGS[0], "citations": citations}]
    hunt_id = _seed_confirmed_hunt(flagged_client, findings=findings)
    doc = {**_CITED_DOC, "_id": citations[0]}
    mock_draft = AsyncMock(return_value=_canned_draft())
    search = AsyncMock(return_value=EsSearchResult(total=1, took_ms=1, hits=[doc]))
    with (
        patch(_DRAFT_DETECTION, mock_draft),
        patch.object(ElasticClient, "search", search),
        patch(_QUERY_EVENTS_OQL, AsyncMock(return_value=_es_result(0))),
    ):
        resp = flagged_client.post(f"/api/v1/hunts/{hunt_id}/findings/0/draft-detection")
    assert resp.status_code == 200
    assert search.await_args is not None
    fetched_ids = search.await_args.args[1]["ids"]["values"]
    assert fetched_ids == citations[:5]
    assert mock_draft.await_args is not None
    evidence = mock_draft.await_args.kwargs["evidence"]
    assert "… and 5 more" in evidence
    assert citations[19] in evidence
    assert citations[20] not in evidence.split("… and 5 more")[0]


def test_hunt_finding_route_dry_run_anchored_on_cited_timestamp(
    flagged_client: TestClient,
) -> None:
    """The would-have-fired window must bracket when the cited activity
    happened, not the 30 days ending now."""
    hunt_id = _seed_confirmed_hunt(flagged_client)
    mock_query = AsyncMock(return_value=_es_result(1, hits=[{"_id": "hit-1"}]))
    with (
        patch(_DRAFT_DETECTION, AsyncMock(return_value=_canned_draft())),
        _cited_docs_search(),
        patch(_QUERY_EVENTS_OQL, mock_query),
    ):
        resp = flagged_client.post(f"/api/v1/hunts/{hunt_id}/findings/0/draft-detection")
    assert resp.status_code == 200
    assert mock_query.await_args is not None
    anchor = mock_query.await_args.kwargs["time_anchor"]
    assert anchor == datetime(2026, 7, 4, 12, 0, tzinfo=UTC)


# ── Provenance stamp ─────────────────────────────────────────────────────────


def test_hunt_finding_route_stamps_provenance(flagged_client: TestClient) -> None:
    """The exported YAML must carry its origin — a comment naming the hunt,
    finding, and confirming investigation, plus a Sigma ``author`` key — and
    stamping must not cost the rule its schema validity."""
    hunt_id = _seed_confirmed_hunt(flagged_client)
    with (
        patch(_DRAFT_DETECTION, AsyncMock(return_value=_canned_draft())),
        _cited_docs_search(),
        patch(_QUERY_EVENTS_OQL, AsyncMock(return_value=_es_result(0))),
    ):
        resp = flagged_client.post(f"/api/v1/hunts/{hunt_id}/findings/0/draft-detection")
    assert resp.status_code == 200
    body = resp.json()
    sigma_yaml = body["sigma_yaml"]
    assert f"# drafted by soc-ai from hunt {hunt_id} finding 0" in sigma_yaml
    assert "01TESTDETECTROUTE0000000001" in sigma_yaml  # the confirming investigation
    assert "author: soc-ai" in sigma_yaml
    assert body["schema_ok"] is True


def test_hunt_finding_route_draft_near_cap_survives_provenance_stamp(
    flagged_client: TestClient,
) -> None:
    """The sigma_yaml max_length cap validates the DRAFTER's output; the
    server-side provenance stamp then grows it ~60-130 chars. A successful
    draft sitting a few chars under the cap must still land as a 200 —
    FastAPI re-validating the stamped response used to 500 it
    (``response_model=None`` on the route is the fix)."""
    cap = next(
        m.max_length
        for m in SigmaDraft.model_fields["sigma_yaml"].metadata
        if hasattr(m, "max_length")
    )
    base = _canned_draft().sigma_yaml
    padded = base + "# " + "x" * (cap - 5 - len(base) - 3) + "\n"
    assert len(padded) == cap - 5
    hunt_id = _seed_confirmed_hunt(flagged_client)
    with (
        patch(_DRAFT_DETECTION, AsyncMock(return_value=_canned_draft(sigma_yaml=padded))),
        _cited_docs_search(),
        patch(_QUERY_EVENTS_OQL, AsyncMock(return_value=_es_result(0))),
    ):
        resp = flagged_client.post(f"/api/v1/hunts/{hunt_id}/findings/0/draft-detection")
    assert resp.status_code == 200
    sigma_yaml = resp.json()["sigma_yaml"]
    assert len(sigma_yaml) > cap  # the stamp legitimately grew it past the drafter cap
    assert "author: soc-ai" in sigma_yaml


# ── Model-failure mapping (never a bare 500) ─────────────────────────────────


def test_hunt_finding_route_model_failure_maps_to_502(flagged_client: TestClient) -> None:
    """Retry exhaustion / gateway failure from the drafter must land as a
    mapped 502, not an unhandled 500."""
    hunt_id = _seed_confirmed_hunt(flagged_client)
    with (
        patch(_DRAFT_DETECTION, AsyncMock(side_effect=UnexpectedModelBehavior("boom"))),
        _cited_docs_search(),
    ):
        resp = flagged_client.post(f"/api/v1/hunts/{hunt_id}/findings/0/draft-detection")
    assert resp.status_code == 502
    assert resp.json()["detail"]["reason"] == "draft_model_unavailable"


def test_hunt_finding_route_draft_timeout_maps_to_504(flagged_client: TestClient) -> None:
    hunt_id = _seed_confirmed_hunt(flagged_client)
    with (
        patch(_DRAFT_DETECTION, AsyncMock(side_effect=TimeoutError())),
        _cited_docs_search(),
    ):
        resp = flagged_client.post(f"/api/v1/hunts/{hunt_id}/findings/0/draft-detection")
    assert resp.status_code == 504
    assert resp.json()["detail"]["reason"] == "draft_timeout"


# ── Investigation route ──────────────────────────────────────────────────────


def test_investigation_route_happy_path(flagged_client: TestClient) -> None:
    hunt_id = _seed_hunt(flagged_client)
    inv_id = _seed_investigation(flagged_client, hunt_id=hunt_id, finding_ordinal=0)
    mock_query = AsyncMock(return_value=_es_result(2))
    with (
        patch(_DRAFT_DETECTION, AsyncMock(return_value=_canned_draft())),
        _cited_docs_search(),
        patch(_QUERY_EVENTS_OQL, mock_query),
    ):
        resp = flagged_client.post(f"/api/v1/investigations/{inv_id}/draft-detection")
    assert resp.status_code == 200
    body = resp.json()
    assert body["dry_run"]["ran"] is True
    # Provenance names the hunt, finding, and this investigation.
    assert f"# drafted by soc-ai from hunt {hunt_id} finding 0" in body["sigma_yaml"]
    assert inv_id in body["sigma_yaml"]


def test_investigation_route_non_hunt_kind_409(flagged_client: TestClient) -> None:
    inv_id = _seed_investigation(
        flagged_client, kind="suricata", hunt_id=None, finding_ordinal=None
    )
    with patch(_DRAFT_DETECTION, AsyncMock(return_value=_canned_draft())):
        resp = flagged_client.post(f"/api/v1/investigations/{inv_id}/draft-detection")
    assert resp.status_code == 409
    assert resp.json()["detail"]["reason"] == "not_a_hunt_investigation"


def test_investigation_route_running_409(flagged_client: TestClient) -> None:
    hunt_id = _seed_hunt(flagged_client)
    inv_id = _seed_investigation(
        flagged_client, status="running", verdict=None, hunt_id=hunt_id, finding_ordinal=0
    )
    with patch(_DRAFT_DETECTION, AsyncMock(return_value=_canned_draft())):
        resp = flagged_client.post(f"/api/v1/investigations/{inv_id}/draft-detection")
    assert resp.status_code == 409
    assert resp.json()["detail"]["reason"] == "not_complete"


def test_investigation_route_false_positive_verdict_409(flagged_client: TestClient) -> None:
    """Confirm-first on the investigation route: a completed run whose verdict
    is not true_positive must not draft a detection."""
    hunt_id = _seed_hunt(flagged_client)
    inv_id = _seed_investigation(
        flagged_client, verdict="false_positive", hunt_id=hunt_id, finding_ordinal=0
    )
    with patch(_DRAFT_DETECTION, AsyncMock(return_value=_canned_draft())):
        resp = flagged_client.post(f"/api/v1/investigations/{inv_id}/draft-detection")
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["reason"] == "not_confirmed_true_positive"
    assert "true positive" in detail["hint"]


def test_investigation_route_deleted_hunt_404(flagged_client: TestClient) -> None:
    inv_id = _seed_investigation(
        flagged_client, hunt_id="01HUNTGONE00000000000000000", finding_ordinal=0
    )
    with patch(_DRAFT_DETECTION, AsyncMock(return_value=_canned_draft())):
        resp = flagged_client.post(f"/api/v1/investigations/{inv_id}/draft-detection")
    assert resp.status_code == 404
    assert resp.json()["detail"]["reason"] == "hunt_not_found"


def test_investigation_route_ordinal_out_of_range_404(flagged_client: TestClient) -> None:
    hunt_id = _seed_hunt(flagged_client)
    inv_id = _seed_investigation(flagged_client, hunt_id=hunt_id, finding_ordinal=9)
    with patch(_DRAFT_DETECTION, AsyncMock(return_value=_canned_draft())):
        resp = flagged_client.post(f"/api/v1/investigations/{inv_id}/draft-detection")
    assert resp.status_code == 404
    assert resp.json()["detail"]["reason"] == "finding_not_found"


# ── Egress guard wiring (closes the confirmed leak) ─────────────────────────


def test_hunt_finding_route_builds_and_passes_guard_when_redaction_on(
    redacted_client: TestClient,
) -> None:
    """analyst_cloud_redaction=True: the route builds a guard (via the shared
    runbook_promotion._build_guard helper) and passes it into draft_detection
    — the whole point of the fix, since draft_detection only sanitizes the
    outbound prompt when a guard is given."""
    hunt_id = _seed_confirmed_hunt(redacted_client)
    fake_guard = object()
    mock_draft = AsyncMock(return_value=_canned_draft())
    with (
        patch(_BUILD_GUARD, AsyncMock(return_value=fake_guard)),
        patch(_DRAFT_DETECTION, mock_draft),
        _cited_docs_search(),
        patch(_QUERY_EVENTS_OQL, AsyncMock(return_value=_es_result(0))),
    ):
        resp = redacted_client.post(f"/api/v1/hunts/{hunt_id}/findings/0/draft-detection")
    assert resp.status_code == 200
    assert mock_draft.await_args is not None
    assert mock_draft.await_args.kwargs["guard"] is fake_guard


def test_hunt_finding_route_guard_none_when_redaction_off(flagged_client: TestClient) -> None:
    """The default (analyst_cloud_redaction=False): guard=None, same as
    before the fix — no cloud egress concern, no guard overhead."""
    hunt_id = _seed_confirmed_hunt(flagged_client)
    mock_draft = AsyncMock(return_value=_canned_draft())
    with (
        patch(_BUILD_GUARD) as mock_build_guard,
        patch(_DRAFT_DETECTION, mock_draft),
        _cited_docs_search(),
        patch(_QUERY_EVENTS_OQL, AsyncMock(return_value=_es_result(0))),
    ):
        resp = flagged_client.post(f"/api/v1/hunts/{hunt_id}/findings/0/draft-detection")
    assert resp.status_code == 200
    assert mock_draft.await_args is not None
    assert mock_draft.await_args.kwargs["guard"] is None
    mock_build_guard.assert_not_called()


def test_investigation_route_builds_and_passes_guard_when_redaction_on(
    redacted_client: TestClient,
) -> None:
    """Same guard wiring on the investigation-keyed route."""
    hunt_id = _seed_hunt(redacted_client)
    inv_id = _seed_investigation(redacted_client, hunt_id=hunt_id, finding_ordinal=0)
    fake_guard = object()
    mock_draft = AsyncMock(return_value=_canned_draft())
    with (
        patch(_BUILD_GUARD, AsyncMock(return_value=fake_guard)),
        patch(_DRAFT_DETECTION, mock_draft),
        _cited_docs_search(),
        patch(_QUERY_EVENTS_OQL, AsyncMock(return_value=_es_result(0))),
    ):
        resp = redacted_client.post(f"/api/v1/investigations/{inv_id}/draft-detection")
    assert resp.status_code == 200
    assert mock_draft.await_args is not None
    assert mock_draft.await_args.kwargs["guard"] is fake_guard


def test_hunt_finding_route_egress_residue_returns_502(flagged_client: TestClient) -> None:
    """Fail-closed redaction blocked the outbound prompt: draft_detection
    raises EgressResidueError, and the route must surface it as a clean 502
    with the leaked COUNT only — never the leaked value — mirroring
    routes_runbooks.promote_runbook's egress_blocked mapping. Never a bare
    500: an analyst-facing route must explain a privacy-gate refusal."""
    hunt_id = _seed_confirmed_hunt(flagged_client)
    with (
        patch(_DRAFT_DETECTION, AsyncMock(side_effect=EgressResidueError(["10.0.0.1 leaked"]))),
        _cited_docs_search(),
    ):
        resp = flagged_client.post(f"/api/v1/hunts/{hunt_id}/findings/0/draft-detection")
    assert resp.status_code == 502
    detail = resp.json()["detail"]
    assert detail["reason"] == "egress_blocked"
    assert detail["leaked_count"] == 1
    assert "10.0.0.1" not in resp.text


def test_investigation_route_egress_residue_returns_502(flagged_client: TestClient) -> None:
    hunt_id = _seed_hunt(flagged_client)
    inv_id = _seed_investigation(flagged_client, hunt_id=hunt_id, finding_ordinal=0)
    with (
        patch(_DRAFT_DETECTION, AsyncMock(side_effect=EgressResidueError(["10.0.0.1 leaked"]))),
        _cited_docs_search(),
    ):
        resp = flagged_client.post(f"/api/v1/investigations/{inv_id}/draft-detection")
    assert resp.status_code == 502
    detail = resp.json()["detail"]
    assert detail["reason"] == "egress_blocked"
    assert detail["leaked_count"] == 1
    assert "10.0.0.1" not in resp.text
