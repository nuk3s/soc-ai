"""The draft confirm box shows the draft (dogfood 2026-10-06 W8).

The box showed the id and one dry-run line. The definition was readable only
after the save. A saved draft repeated two Suricata rule names that raise
alerts already, its dry run found nothing because the source documents were
older than the window, two drafts of one finding got two ids, and the version
note numbered findings from 0 while the page numbers them from F1.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.api.webui.routes_analytics import _version_why
from soc_ai.config import Settings
from soc_ai.hunting.draft_review import alert_rule_repeats, logic_sentence, source_sentence
from soc_ai.hunting.spec import parse_spec
from soc_ai.main import create_app
from soc_ai.store import hunts as hunt_svc

from tests.test_analytic_drafter import GOOD_YAML
from tests.test_hunts_api import _draft_patches

_SURICATA_YAML = """
id: local-http-service-executes-id
title: An HTTP service executes the id command
description: For the review test.
level: high
scope_field: destination.ip
scope_kind: host
detection:
  all:
    - field: event.dataset
      value: suricata.alert
    - field: rule.name
      op: one_of
      value:
        - ET WEB_SERVER Possible id command
        - ET ATTACK_RESPONSE id check returned root
"""


def test_the_logic_reads_as_one_sentence() -> None:
    sentence = logic_sentence(parse_spec(GOOD_YAML))
    assert sentence == (
        "It matches a document where event.code is 4769 and "
        "winlog.event_data.TicketEncryptionType is 0x17, grouped by source.ip."
    )


def test_a_logic_of_rule_names_alone_repeats_the_alerts() -> None:
    assert alert_rule_repeats(parse_spec(_SURICATA_YAML)) == (
        "This analytic repeats 2 Suricata rules. They raise alerts already."
    )
    # Negative controls: a behaviour clause beside the rule name is new logic,
    # and a logic with no rule name repeats nothing.
    behaviour = _SURICATA_YAML.replace(
        "    - field: rule.name",
        "    - field: http.request.method\n      value: POST\n    - field: rule.name",
    )
    assert alert_rule_repeats(parse_spec(behaviour)) is None
    assert alert_rule_repeats(parse_spec(GOOD_YAML)) is None


def test_the_source_line_names_the_old_documents() -> None:
    assert source_sentence(cited=3, matched=0, older=3, window_days=30) == (
        "Source finding: 0 of 3 documents match. They are older than the 30-day dry run."
    )
    # Negative controls: a clean match says so, a missed match says so, and a
    # check that did not run says nothing.
    assert source_sentence(cited=3, matched=3, older=0, window_days=30) == (
        "Source finding: 3 of 3 documents match."
    )
    assert source_sentence(cited=3, matched=1, older=0, window_days=30) == (
        "Source finding: 1 of 3 documents match. The logic misses 2 of them."
    )
    assert source_sentence(cited=3, matched=None, older=3, window_days=30) is None


def test_the_version_note_numbers_findings_from_f1() -> None:
    assert _version_why("drafted from hunt 01ABC finding 1") == (
        "Drafted from finding F2 of hunt 01ABC."
    )
    # Negative control: an analyst's reason is left as typed.
    assert _version_why("noisy on the backup host") == "noisy on the backup host"
    assert _version_why(None) is None


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


_CITED = ["tel-doc-000001", "tel-doc-000002", "tel-doc-000003"]


def _seed(client: TestClient) -> str:
    report: dict[str, Any] = {
        "findings": [
            {
                "title": "An RC4 service ticket is issued to a workstation account",
                "detail": "d",
                "severity": "high",
                "category": "threat",
                "hosts": ["198.51.100.7"],
                "citations": _CITED,
            }
        ],
        "narrative": "n",
    }

    async def go() -> str:
        async with client.app.state.db_sessionmaker() as db:
            hunt = await hunt_svc.create(db, objective="hunt for rc4", started_by="t")
            await hunt_svc.finalize(db, hunt.id, status="complete", narrative="n", report=report)
            return hunt.id

    return asyncio.run(go())


def _old_docs() -> list[dict[str, Any]]:
    stamp = (datetime.now(UTC) - timedelta(days=34)).isoformat().replace("+00:00", "Z")
    return [{"_id": i, "_source": {"@timestamp": stamp}} for i in _CITED]


def test_the_preview_carries_the_draft_in_words(client: TestClient) -> None:
    hunt_id = _seed(client)
    stack, _model = _draft_patches(cited=AsyncMock(return_value=_old_docs()))
    with (
        stack,
        patch(
            "soc_ai.api.webui.routes_detection.count_cited_matches",
            AsyncMock(return_value=0),
        ),
    ):
        res = client.post(
            f"/api/v1/hunts/{hunt_id}/findings/0/draft-analytic", json={"preview": True}
        )
    assert res.status_code == 200, res.text
    review = res.json()["review"]
    assert review["title"] == "An RC4 service ticket is issued to a workstation account"
    assert review["logic"].startswith("It matches a document where event.code is 4769")
    assert review["false_positives"] == ["Windows 7 clients negotiate RC4."]
    assert review["source"] == (
        "Source finding: 0 of 3 documents match. They are older than the 30-day dry run."
    )
    assert review["repeats_alerts"] is None


def test_a_second_draft_of_one_finding_keeps_the_first_id(client: TestClient) -> None:
    hunt_id = _seed(client)
    url = f"/api/v1/hunts/{hunt_id}/findings/0/draft-analytic"
    stack, _model = _draft_patches()
    with stack:
        first = client.post(url, json={"preview": True}).json()
    renamed = GOOD_YAML.replace("local-rc4-ticket-from-workstation", "local-rc4-ticket-again")
    stack, _model = _draft_patches(spec_yaml=renamed)
    with stack:
        second = client.post(url, json={"preview": True}).json()
    assert first["analytic_id"] == "local-rc4-ticket-from-workstation"
    assert second["analytic_id"] == first["analytic_id"]
    assert "id: local-rc4-ticket-from-workstation" in second["spec_yaml"]
    assert "local-rc4-ticket-again" not in second["spec_yaml"]

    # Negative control: another finding keeps the id the model names.
    other = _seed(client)
    stack, _model = _draft_patches(spec_yaml=renamed)
    with stack:
        third = client.post(
            f"/api/v1/hunts/{other}/findings/0/draft-analytic", json={"preview": True}
        ).json()
    assert third["analytic_id"] == "local-rc4-ticket-again"
