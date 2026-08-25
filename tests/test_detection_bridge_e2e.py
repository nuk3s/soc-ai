"""Hermetic Zerologon draft e2e for the detection bridge (1.3 slice 3, Task 8).

A mostly-real path with no lab dependency: a scripted drafter model + the mock
ES from ``scripts/demo/mock_es.py`` serving the packaged
``DETECTION_FIXTURE_DOCS`` (a Zerologon-shaped ``zeek.dce_rpc`` cluster). Unlike
``test_detection_grounding.py`` — which hands ``dry_run_detection`` a
hand-shaped ``EsSearchResult`` — here the dry run's OQL is really parsed,
whitelist-validated, translated to ES DSL, and MATCHED against the fixture docs
by the mock, so the would-have-fired count is computed, not asserted.

Three things this proves that the unit tests do not:

1. **The bridge fires end to end.** Through the real
   ``POST /hunts/{id}/findings/{ordinal}/draft-detection`` route: a Zerologon
   finding → real ``draft_detection`` (scripted model) → ``validate_sigma_yaml``
   → real ``dry_run_detection`` over the mock grid returns ``ran=True`` with a
   real ``hit_count`` and citable ``sample_ids``, and ``schema_ok`` + the
   grounding rationale ride back inline for the review pane.
2. **It is export-only.** Driving the pipeline directly, the ONLY ES method it
   ever touches is ``search`` — no ``index``/``create``/``bulk``/``update``/
   ``delete``; there is no Security Onion detection-write path in the arc at all.
3. **The fixture serves the slice-2 analytics tools too.** ``dcerpc_histogram``
   reads the same fixture through a real ``ElasticClient`` and flags the
   Zerologon operation with the source attribution and sample ids a promotion
   would anchor on.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic_ai.messages import (
    ModelMessage,
    ModelRequest,
    ModelResponse,
    ToolCallPart,
    UserPromptPart,
)
from pydantic_ai.models.function import AgentInfo, FunctionModel
from scripts.demo.mock_es import DETECTION_FIXTURE_DOCS, _search_response_from_docs
from soc_ai.config import Settings
from soc_ai.detection.drafter import draft_detection
from soc_ai.detection.validators import dry_run_detection, validate_sigma_yaml
from soc_ai.main import create_app
from soc_ai.so_client import fields as so_fields
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store import hunts as hunt_svc
from soc_ai.store.models import Investigation
from soc_ai.tools.analytics import dcerpc_histogram

_BUILD = "soc_ai.detection.drafter.build_synthesizer_model"

# The confirmed hunt finding: its discriminating evidence is the specific
# operation, not "some dce_rpc traffic happened". RFC5737 addressing only.
ZEROLOGON_FINDING: dict[str, Any] = {
    "title": "Zerologon-pattern DCE-RPC authentication anomaly",
    "detail": (
        "198.51.100.23 sent a burst of NetrServerAuthenticate3 calls to the domain "
        "controller's netlogon pipe (preceded by NetrServerReqChallenge)."
    ),
    "severity": "critical",
    "category": "threat",
    "hosts": ["198.51.100.23"],
    "citations": ["zl-dce-000001", "zl-dce-000002"],
}

# The GROUNDED draft the scripted model returns: keys on the specific
# operations the evidence named, in the whitelisted zeek.* field form.
_GROUNDED_DRAFT: dict[str, Any] = {
    "title": "Zerologon NetrServerAuthenticate3 anomaly",
    "sigma_yaml": (
        "title: Zerologon NetrServerAuthenticate3 anomaly\n"
        "logsource:\n"
        "  category: dce_rpc\n"
        "detection:\n"
        "  selection:\n"
        "    zeek.dce_rpc.operation:\n"
        "      - NetrServerAuthenticate3\n"
        "      - NetrServerReqChallenge\n"
        "  condition: selection\n"
    ),
    "oql": (
        "event.dataset:zeek.dce_rpc AND zeek.dce_rpc.operation:"
        "(NetrServerAuthenticate3 OR NetrServerReqChallenge)"
    ),
    "rationale": (
        "Keys on the specific NetrServerAuthenticate3/NetrServerReqChallenge operations "
        "the evidence named, not any dce_rpc call, so routine RMM/admin traffic won't fire."
    ),
}

# The count the drafted rule would have fired on across the fixture: the 8
# NetrServerAuthenticate3 + 3 NetrServerReqChallenge docs (benign ops excluded).
_EXPECTED_HITS = 11

_WRITE_METHODS = ("index", "create", "bulk", "update", "delete")


def _user_prompt(messages: list[ModelMessage]) -> str:
    for msg in messages:
        if isinstance(msg, ModelRequest):
            for part in msg.parts:
                if isinstance(part, UserPromptPart):
                    assert isinstance(part.content, str)
                    return part.content
    raise AssertionError("no UserPromptPart in model request")


def _drafter_model(captured: dict[str, Any]) -> FunctionModel:
    """A FunctionModel that records the outbound prompt and returns the grounded draft."""

    def _fn(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        captured["prompt"] = _user_prompt(messages)
        return ModelResponse(
            parts=[ToolCallPart(tool_name=info.output_tools[0].name, args=_GROUNDED_DRAFT)]
        )

    return FunctionModel(_fn)


def _mock_grid_search(**kwargs: Any) -> dict[str, Any]:
    """Route an ElasticClient search to the mock ES fixture-response builder."""
    return _search_response_from_docs(kwargs.get("body") or {}, DETECTION_FIXTURE_DOCS)


def _elastic_over_mock(settings: Settings) -> tuple[ElasticClient, AsyncMock]:
    """A real ``ElasticClient`` whose raw search dispatches to the mock fixture.

    The whole read path below the client is real (query_events_oql → validate_oql
    → ast_to_es_dsl → ElasticClient.search); only the transport is the mock.
    """
    fake_es = AsyncMock()
    fake_es.search = AsyncMock(side_effect=_mock_grid_search)
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        client = ElasticClient(settings)
    return client, fake_es


@contextmanager
def _app_client(settings: Settings) -> Iterator[tuple[TestClient, AsyncMock]]:
    """A real ``create_app`` + ``TestClient`` whose grid is the mock fixture."""
    fake_es = AsyncMock()
    fake_es.search = AsyncMock(side_effect=_mock_grid_search)
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client, fake_es


@pytest.fixture
def flagged_settings(settings_kratos: Settings) -> Settings:
    """Detection bridge enabled (default off); cloud redaction off (guard=None)."""
    return settings_kratos.model_copy(update={"sigma_authoring_enabled": True})


def _seed_hunt(client: TestClient) -> str:
    async def _go() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            hunt = await hunt_svc.create(db, objective="hunt for lateral movement", started_by="a")
            await hunt_svc.finalize(
                db,
                hunt.id,
                status="complete",
                narrative="one workstation authenticated abnormally to the DC",
                report={"findings": [ZEROLOGON_FINDING]},
            )
            # Confirm-first doctrine: a detection drafts only from a completed
            # true_positive investigation of the finding. Seed that promotion.
            db.add(
                Investigation(
                    id="01TESTBRIDGEE2E00000000001",
                    alert_es_id="zl-dce-000001",
                    kind="hunt",
                    status="complete",
                    verdict="true_positive",
                    hunt_id=hunt.id,
                    finding_ordinal=0,
                )
            )
            await db.commit()
            return hunt.id

    return asyncio.run(_go())


# ── 1. The bridge fires end to end, through the real route ───────────────────


def test_route_drafts_grounded_rule_whose_dry_run_fires_on_the_fixture(
    flagged_settings: Settings,
) -> None:
    captured: dict[str, Any] = {}
    with _app_client(flagged_settings) as (client, _fake_es):
        hunt_id = _seed_hunt(client)
        with patch(_BUILD, return_value=_drafter_model(captured)):
            resp = client.post(f"/api/v1/hunts/{hunt_id}/findings/0/draft-detection")

    assert resp.status_code == 200
    body = resp.json()

    # Grounding: the discriminating operation reached the model.
    assert "NetrServerAuthenticate3" in captured["prompt"]

    # The rule keys on that operation (not a bare-dataset shape) and validates.
    assert "NetrServerAuthenticate3" in body["oql"]
    assert body["schema_ok"] is True
    assert body["validator_note"] is None

    # Provenance: the grounding rationale rides back inline for the review pane.
    assert body["rationale"]

    # The would-have-fired dry run really ran the OQL path over the fixture.
    dry_run = body["dry_run"]
    assert dry_run["ran"] is True
    assert dry_run["hit_count"] == _EXPECTED_HITS
    assert dry_run["error"] is None
    # Citable evidence: sample ids resolvable to real fixture docs.
    assert dry_run["sample_ids"]
    assert all(sid.startswith("zl-dce") for sid in dry_run["sample_ids"])


# ── 2. The arc is export-only: reads only, no Security Onion write ────────────


async def test_draft_bridge_is_export_only_and_never_writes(settings_kratos: Settings) -> None:
    """Draft → validate → dry-run touches ES for READS only. There is no
    SO detection-write path in the arc, so the export-only guarantee holds
    structurally, not by a flag."""
    captured: dict[str, Any] = {}
    with patch(_BUILD, return_value=_drafter_model(captured)):
        draft = await draft_detection(
            settings_kratos, finding=ZEROLOGON_FINDING, evidence="Cited: zl-dce-01, zl-dce-02"
        )
    validated = validate_sigma_yaml(draft)
    assert validated.schema_ok is True

    elastic, fake_es = _elastic_over_mock(settings_kratos)
    result = await dry_run_detection(validated, elastic=elastic, settings=settings_kratos)

    assert result.dry_run is not None
    assert result.dry_run.ran is True
    assert result.dry_run.hit_count == _EXPECTED_HITS

    fake_es.search.assert_awaited()  # the read path really dispatched
    for method in _WRITE_METHODS:
        getattr(fake_es, method).assert_not_called()


# ── 3. The same fixture feeds the slice-2 analytics tools ────────────────────


async def test_fixture_serves_dcerpc_histogram_with_citable_evidence(
    settings_kratos: Settings,
) -> None:
    """The Zerologon fixture the draft bridge dry-runs against is the same one a
    hunt's dcerpc_histogram sweep reads — it flags the dangerous operation with
    the source attribution and sample ids a finding would then anchor on."""
    so_fields._clear_agg_field_cache()
    elastic, _ = _elastic_over_mock(settings_kratos)
    result = await dcerpc_histogram(elastic=elastic, settings=settings_kratos)

    assert "error" not in result
    counts = {item["operation"]: item["count"] for item in result["items"]}
    assert counts["NetrServerAuthenticate3"] == 8

    flagged = {f["operation"] for f in result["flagged"]}
    assert "NetrServerAuthenticate3" in flagged
    auth = next(f for f in result["flagged"] if f["operation"] == "NetrServerAuthenticate3")
    assert auth["sources"] == ["198.51.100.23"]
    assert auth["sample_ids"]
    assert all(sid.startswith("zl-dce") for sid in auth["sample_ids"])
