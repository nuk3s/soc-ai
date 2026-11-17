"""The text of a run inside an authorized activity record, at read time.

Polish review 2026-11-13: under the banner "Authorized activity: php2shell
security testing" the run text said "No record of authorized testing covers
this traffic." The triage model never reads an authorization, by design, so
every run inside a scope can say this. The owner rule: an ungrounded
statement is grounded or stripped, never bannered. The console drops such a
sentence when it reads a run whose authorization holds. The store keeps the
report, so a revoke returns the text.
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
from soc_ai.main import create_app
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.authorized_activity import (
    Mark,
    denies_authorization,
    drop_authorization_denials,
    run_text_for_mark,
)
from soc_ai.store.models import AuthorizedActivity, Investigation

PROD_TEXT = (
    "Host 10.40.50.7 sent a PHP exploit request to 10.20.30.5:8503. The server returned HTTP 200 "
    "with a 7-byte body. No record of authorized testing covers this traffic."
)


def _mark(*, holds: bool = True, state: str = "active") -> Mark:
    return Mark(
        id=7,
        label="php2shell security testing",
        state=state,
        expires_at=datetime(2026, 11, 20, tzinfo=UTC),
        by="analyst",
        holds=holds,
    )


@pytest.mark.parametrize(
    "sentence",
    [
        "No record of authorized testing covers this traffic.",
        "The source is not an authorised scanner.",
        "None of the hosts is a sanctioned scanner.",
        "The traffic arrived without any pentest notice.",
        "The case lacks a penetration test ticket.",
        "A red team engagement is absent from the records.",
        "soc-ai cannot find an approved test for this source.",
        "The analyst could not find an approved scan window.",
        "There is no approved activity on file.",
        "This isn't an authorized test.",
    ],
)
def test_a_sentence_that_denies_an_authorization_is_named(sentence: str) -> None:
    assert denies_authorization(sentence)


@pytest.mark.parametrize(
    "sentence",
    [
        # No authorization term: the sentence stays.
        "No case exists.",
        "The server did not answer.",
        # An authorization term with no negation: the sentence stays.
        "The scan was authorized by the owner.",
        "A red team ran the test from the lab range.",
    ],
)
def test_a_sentence_with_one_part_only_is_not_named(sentence: str) -> None:
    assert not denies_authorization(sentence)


def test_the_denial_goes_and_every_other_sentence_stays() -> None:
    assert drop_authorization_denials(PROD_TEXT) == (
        "Host 10.40.50.7 sent a PHP exploit request to 10.20.30.5:8503. The server returned "
        "HTTP 200 with a 7-byte body."
    )


def test_a_list_keeps_its_shape_and_its_other_lines() -> None:
    text = "- The payload is a web shell.\n- No pentest window covers it.\n\nNo case exists."
    assert drop_authorization_denials(text) == "- The payload is a web shell.\n\nNo case exists."


def test_text_that_would_lose_every_sentence_comes_back_whole() -> None:
    text = "No record of authorized testing covers this traffic."
    assert drop_authorization_denials(text) == text
    assert drop_authorization_denials("") == ""


def test_text_with_nothing_to_drop_comes_back_byte_for_byte() -> None:
    text = "No case exists.  The scan was authorized by the owner.\n\n\nThe end."
    assert drop_authorization_denials(text) == text


def test_a_mark_that_holds_drops_the_denial() -> None:
    assert run_text_for_mark(PROD_TEXT, _mark()) != PROD_TEXT
    # An expired authorization still holds its runs.
    assert run_text_for_mark(PROD_TEXT, _mark(state="expired")) != PROD_TEXT


def test_an_unmarked_run_and_a_revoked_mark_keep_every_sentence() -> None:
    """Negative controls: the drop needs a mark that holds."""
    assert run_text_for_mark(PROD_TEXT, None) == PROD_TEXT
    assert run_text_for_mark(PROD_TEXT, _mark(holds=False, state="revoked")) == PROD_TEXT


# ── The API reads the text under the mark ─────────────────────────────────

RULE = "ET EXPLOIT Example Upload Request"
SAID = "The upload request carries a web shell. No record of authorized testing covers it."
KEPT = "The upload request carries a web shell."
ACTION = {
    "tool_name": "escalate_to_case",
    "tool_args": {"case_title": "Upload", "case_description": "Exploit requests."},
    "rationale": "Open a case for the exploit. No pentest window covers this source.",
}


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


def _do(client: TestClient, work: Any) -> Any:
    async def go() -> Any:
        async with client.app.state.db_sessionmaker() as db:
            return await work(db)

    return asyncio.run(go())


def _seed_authorization(client: TestClient, *, revoked: bool = False) -> int:
    async def work(db: Any) -> int:
        now = utcnow()
        row = AuthorizedActivity(
            label="php2shell security testing",
            sources=[{"address": "10.40.50.7", "machine_key": "agent:d1", "name": "devbox"}],
            target_address="10.20.30.5",
            target_machine_key="ip:m1",
            rule_names=[RULE],
            rule_class="exploit_attempt",
            starts_at=now - timedelta(days=2),
            expires_at=now + timedelta(days=5),
            created_by="analyst",
            revoked_at=now if revoked else None,
        )
        db.add(row)
        await db.commit()
        return int(row.id)

    return int(_do(client, work))


def _seed_run(client: TestClient, alert_id: str, authorization: int | None) -> str:
    async def work(db: Any) -> str:
        inv = await inv_svc.create(
            db,
            alert_es_id=alert_id,
            started_by="auto-triage",
            rule_name=RULE,
            src_ip="10.40.50.7",
            dest_ip="10.20.30.5",
        )
        await inv_svc.finalize(
            db,
            inv.id,
            status="complete",
            verdict="true_positive",
            confidence=0.85,
            rationale=SAID,
            summary=SAID,
            report={
                "verdict": "true_positive",
                "confidence": 0.85,
                "summary": SAID,
                "recommended_actions": [ACTION],
            },
        )
        row = await db.get(Investigation, inv.id)
        row.created_at = (utcnow() - timedelta(minutes=30)).replace(tzinfo=None)
        row.authorization_id = authorization
        await db.commit()
        return str(inv.id)

    return str(_do(client, work))


def _read(client: TestClient, run_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    rows = client.get("/api/v1/investigations", params={"range": "all"}).json()["rows"]
    row = next(r for r in rows if r["id"] == run_id)
    with patch("soc_ai.api.webui._timeline._alert_ack_state", AsyncMock(return_value=None)):
        detail = client.get(f"/api/v1/investigations/{run_id}").json()
    return row, detail


def test_the_page_and_the_row_of_a_marked_run_drop_the_denial(client: TestClient) -> None:
    run_id = _seed_run(client, "auth-1", _seed_authorization(client))
    row, detail = _read(client, run_id)
    assert row["headline"] == KEPT
    assert detail["rationale"] == KEPT
    assert detail["summary"][0]["v"] == KEPT
    assert [a["rationale"] for a in detail["actions"]] == ["Open a case for the exploit."]
    # The store keeps the report as the model wrote it.

    async def stored(db: Any) -> str:
        return str((await db.get(Investigation, run_id)).summary)

    assert _do(client, stored) == SAID


@pytest.mark.parametrize("revoked", [None, True])
def test_an_unmarked_run_and_a_revoked_mark_keep_the_text(
    client: TestClient, revoked: bool | None
) -> None:
    """Negative controls: no mark, or a mark that an analyst revoked."""
    mark = None if revoked is None else _seed_authorization(client, revoked=True)
    run_id = _seed_run(client, f"auth-{revoked}", mark)
    row, detail = _read(client, run_id)
    assert row["headline"] == SAID
    assert detail["rationale"] == SAID
    assert detail["summary"][0]["v"] == SAID
    assert [a["rationale"] for a in detail["actions"]] == [ACTION["rationale"]]


def test_the_threat_headline_and_the_alerts_reason_read_under_the_mark() -> None:
    from types import SimpleNamespace

    from soc_ai.api.webui.routes_alerts import _headline
    from soc_ai.api.webui.routes_threats import _what_happened

    run = SimpleNamespace(
        rationale=SAID, summary=SAID, rule_name=RULE, report={"summary": SAID}, authorization_id=7
    )
    assert _what_happened(run, {}, _mark()) == KEPT  # type: ignore[arg-type]
    assert _headline(run, {7: _mark()}) == KEPT  # type: ignore[arg-type]
    # NEGATIVE CONTROLS: no mark, and a revoked mark.
    assert _what_happened(run, {}, None) == SAID  # type: ignore[arg-type]
    revoked = _mark(holds=False, state="revoked")
    assert _what_happened(run, {}, revoked) == SAID  # type: ignore[arg-type]
    assert _headline(run, {7: revoked}) == SAID  # type: ignore[arg-type]
    assert _headline(run, {}) == SAID  # type: ignore[arg-type]


# ── Lead review, 2026-11-13: two cases the first rule got wrong ───────────────


@pytest.mark.parametrize(
    "sentence",
    [
        "The request is an unauthorized file upload, and no benign client sends it.",
        "The source did not stop after the unauthorised read of /etc/passwd.",
    ],
)
def test_a_sentence_about_an_unauthorized_action_is_evidence_and_stays(sentence: str) -> None:
    """ "Unauthorized" describes the action. It denies no authorization record."""
    assert not denies_authorization(sentence)
    assert drop_authorization_denials(sentence) == sentence


def test_a_denial_in_a_closing_clause_goes_and_the_evidence_clause_stays() -> None:
    """The headline of production run 01M7BHDHRBMGQ2RAV6HC266RS6. It is one
    sentence, so the first rule kept it whole and the contradiction stayed."""
    headline = (
        "The tight exploit signature and the matching large chunked POSTs on the wire "
        "confirm an attack wave, and no case or authorization record clears it."
    )
    assert drop_authorization_denials(headline) == (
        "The tight exploit signature and the matching large chunked POSTs on the wire "
        "confirm an attack wave."
    )


def test_a_sentence_that_is_a_denial_in_each_clause_comes_back_whole() -> None:
    text = "No authorization record exists, and no sanctioned test covers it."
    assert drop_authorization_denials(text) == text


def test_a_clause_with_evidence_and_no_denial_is_never_cut() -> None:
    text = "The server answered 200, and the body holds the file."
    assert drop_authorization_denials(text) == text


def test_a_denial_in_the_opening_clause_goes_and_the_evidence_takes_the_capital() -> None:
    text = "No authorization record covers it, and the server answered 200 with the file."
    assert drop_authorization_denials(text) == "The server answered 200 with the file."
