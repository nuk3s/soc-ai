"""The server binds the case text of an Escalate action (review 2026-11-13, D1).

Production held five true positive runs whose Escalate action had empty
arguments: ``{"tool_name": "escalate_to_case", "tool_args": {}}``. The execute
route bound the alert id and nothing else. ``escalate_to_case`` needs a title
and a description, so Execute failed on each of the five runs.

The route now binds both when the model left them empty or sent a value that
is not text. The title is the rule name. The description is the headline of
the run. The analyst override path already bound both the same way.

The tests run the real ``escalate_to_case`` tool against a Security Onion
double, so a test fails when the tool refuses the arguments.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from tests.test_needs_you_count import client  # noqa: F401 - the shared fixture

_RULE = "ET EXPLOIT php2shell CVE-2026-109618 chunked POST"
_HEADLINE = "The captured request body matches the exploit pattern and the server answered 200."
_RATIONALE = "The cited flow shows a deliberate exploit request, so it needs a case."
_ALERT = "9IoyoqEB6RQ6BUvopPsX"


class _Response:
    """One Security Onion answer."""

    def __init__(self, body: dict[str, Any], status_code: int = 200) -> None:
        self.status_code = status_code
        self._body = body
        self.text = str(body)

    def json(self) -> dict[str, Any]:
        return self._body


class _SecurityOnion:
    """Records each write and answers the way a healthy grid does."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    async def request(self, method: str, url: str, **kwargs: Any) -> _Response:
        body = dict(kwargs.get("json") or {})
        self.calls.append((method, url, body))
        if url == "/api/case/":
            return _Response({"id": "case-77"})
        if url == "/api/case/events":
            return _Response({"count": 1})
        return _Response({})

    @property
    def created(self) -> list[dict[str, Any]]:
        return [body for _method, url, body in self.calls if url == "/api/case/"]

    @property
    def attached(self) -> list[str]:
        return [
            str(body["fields"]["soc_id"])
            for _method, url, body in self.calls
            if url == "/api/case/events"
        ]


def _seed(
    client: TestClient,  # noqa: F811 - the fixture
    run_id: str,
    *,
    tool_args: Any,
    rule_name: str | None = _RULE,
    headline: str | None = _HEADLINE,
    rationale: str = _RATIONALE,
) -> None:
    from soc_ai.store.models import Investigation

    at = (datetime.now(UTC) - timedelta(hours=1)).replace(tzinfo=None)
    action = {"tool_name": "escalate_to_case", "tool_args": tool_args, "rationale": rationale}

    async def go() -> None:
        async with client.app.state.db_sessionmaker() as db:
            db.add(
                Investigation(
                    id=run_id,
                    alert_es_id=_ALERT,
                    kind="suricata",
                    rule_name=rule_name,
                    status="complete",
                    verdict="true_positive",
                    confidence=0.85,
                    rationale=headline,
                    report={"verdict": "true_positive", "recommended_actions": [action]},
                    created_at=at,
                    finished_at=at,
                    started_by="scheduler",
                )
            )
            await db.commit()

    asyncio.run(go())


def _execute(client: TestClient, run_id: str) -> tuple[Any, _SecurityOnion]:  # noqa: F811
    grid = _SecurityOnion()
    with (
        patch.object(client.app.state, "auth", grid),
        patch("soc_ai.api.webui.routes_actions._reserve_escalate", AsyncMock(return_value=None)),
    ):
        res = client.post(f"/api/v1/investigations/{run_id}/actions/0/execute")
    return res, grid


# ── The defect ──────────────────────────────────────────────────────────────


def test_an_escalate_with_empty_arguments_opens_the_case(client: TestClient) -> None:  # noqa: F811
    """The stored shape of the five production runs."""
    _seed(client, "INV-EMPTY", tool_args={})
    res, grid = _execute(client, "INV-EMPTY")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["status"] == "executed", body
    assert grid.created == [{"title": _RULE, "description": _HEADLINE}]
    assert grid.attached == [_ALERT]


@pytest.mark.parametrize(
    "tool_args",
    [
        {"case_title": None, "case_description": None},
        {"case_title": "", "case_description": "   "},
        {"case_title": 7, "case_description": ["a", "list"]},
        {"case_title": {"text": "t"}, "case_description": False},
        # The stored report holds no object in place of the arguments.
        None,
        "not an object",
        ["case_title", "case_description"],
    ],
)
def test_a_value_that_is_not_text_is_bound_too(client: TestClient, tool_args: Any) -> None:  # noqa: F811
    _seed(client, "INV-TYPES", tool_args=tool_args)
    res, grid = _execute(client, "INV-TYPES")
    assert res.json()["status"] == "executed", res.text
    assert grid.created == [{"title": _RULE, "description": _HEADLINE}]


def test_one_empty_field_is_bound_and_the_other_is_kept(client: TestClient) -> None:  # noqa: F811
    _seed(client, "INV-HALF", tool_args={"case_title": "Exploit of 10.20.30.164"})
    res, grid = _execute(client, "INV-HALF")
    assert res.json()["status"] == "executed", res.text
    assert grid.created == [{"title": "Exploit of 10.20.30.164", "description": _HEADLINE}]


# ── What the binding falls back to ──────────────────────────────────────────


def test_a_run_with_no_headline_uses_the_reason_of_the_action(client: TestClient) -> None:  # noqa: F811
    _seed(client, "INV-NO-HEAD", tool_args={}, headline=None)
    res, grid = _execute(client, "INV-NO-HEAD")
    assert res.json()["status"] == "executed", res.text
    assert grid.created == [{"title": _RULE, "description": _RATIONALE}]


def test_a_run_with_no_rule_name_and_no_text_still_opens_the_case(client: TestClient) -> None:  # noqa: F811
    _seed(client, "INV-BARE", tool_args={}, rule_name=None, headline=None, rationale="")
    res, grid = _execute(client, "INV-BARE")
    assert res.json()["status"] == "executed", res.text
    assert grid.created == [
        {
            "title": "soc-ai investigation",
            "description": "soc-ai investigation INV-BARE recommends this case.",
        }
    ]


def test_a_long_rule_name_is_cut_to_the_length_of_a_case_title(client: TestClient) -> None:  # noqa: F811
    _seed(client, "INV-LONG", tool_args={}, rule_name="ET " + "X" * 400)
    res, grid = _execute(client, "INV-LONG")
    assert res.json()["status"] == "executed", res.text
    assert len(grid.created[0]["title"]) == 100


# ── Negative controls ───────────────────────────────────────────────────────


def test_the_text_of_the_model_is_kept_when_it_is_present(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL. The binding fills a gap. It does not replace text."""
    _seed(
        client,
        "INV-FULL",
        tool_args={"case_title": "  Exploit of 10.20.30.164  ", "case_description": "Model text."},
    )
    res, grid = _execute(client, "INV-FULL")
    assert res.json()["status"] == "executed", res.text
    assert grid.created == [{"title": "Exploit of 10.20.30.164", "description": "Model text."}]


def test_the_write_target_is_never_taken_from_the_model(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL (F07). The model names another alert and leaves the
    text empty. The case opens on the alert of the run, and no part of the
    case text holds the id that the model sent."""
    _seed(client, "INV-TARGET", tool_args={"alert_id": "ATTACKER-CHOSEN-ID-0001"})
    res, grid = _execute(client, "INV-TARGET")
    assert res.json()["status"] == "executed", res.text
    assert grid.attached == [_ALERT]
    assert "ATTACKER-CHOSEN-ID-0001" not in str(grid.calls)


def test_the_stored_action_is_not_rewritten(client: TestClient) -> None:  # noqa: F811
    """The binding is for the write. The record keeps what the model sent, so
    the receipt still names the action by its stored identity."""
    from soc_ai.store.models import Investigation

    _seed(client, "INV-STORED", tool_args={})
    res, _grid = _execute(client, "INV-STORED")
    assert res.json()["status"] == "executed", res.text

    async def stored() -> Any:
        async with client.app.state.db_sessionmaker() as db:
            run = await db.get(Investigation, "INV-STORED")
            assert run is not None
            return run.report["recommended_actions"][0]["tool_args"]

    assert asyncio.run(stored()) == {}
    detail = client.get("/api/v1/investigations/INV-STORED").json()
    assert detail["actions"][0]["applied"] is True


def test_the_override_path_uses_the_same_default_title() -> None:
    """One rule for the title of a case that has no rule name."""
    from soc_ai.api.webui.routes_actions import _override_actions

    actions = _override_actions(
        "true_positive", user="ana", rule_name=None, headline="Verdict set by ana."
    )
    assert actions[0]["tool_args"] == {
        "case_title": "soc-ai investigation",
        "case_description": "Verdict set by ana.",
    }


# ── The limits of Security Onion (review of the lane, defect 1) ─────────────
#
# Security Onion refuses a case title over 100 BYTES and a description over
# 1000000 bytes (securityonion-soc elasticcasestore.go, SHORT_STRING_MAX and
# LONG_STRING_MAX, checked with Go len()). The first fix cut the bound title at
# 120 characters, and the override path did not cut. Each press then answered
# "title is too long (117/100)" and the action stayed open.


class _StrictSecurityOnion(_SecurityOnion):
    """The double with the title and description rule of the upstream source."""

    async def request(self, method: str, url: str, **kwargs: Any) -> _Response:
        body = dict(kwargs.get("json") or {})
        if url == "/api/case/":
            for field, limit in (("title", 100), ("description", 1_000_000)):
                size = len(str(body.get(field, "")).encode())
                if size > limit:
                    self.calls.append((method, url, body))
                    return _Response({"error": f"{field} is too long ({size}/{limit})"}, 400)
        return await super().request(method, url, **kwargs)


def _execute_strict(client: TestClient, run_id: str) -> tuple[Any, _SecurityOnion]:  # noqa: F811
    grid = _StrictSecurityOnion()
    with (
        patch.object(client.app.state, "auth", grid),
        patch("soc_ai.api.webui.routes_actions._reserve_escalate", AsyncMock(return_value=None)),
    ):
        res = client.post(f"/api/v1/investigations/{run_id}/actions/0/execute")
    return res, grid


_LONG_RULE = "ET EXPLOIT " + "Apache log4j RCE Attempt Obfuscation Observed M2 " * 3  # 158 chars


@pytest.mark.parametrize(
    "tool_args",
    [{}, {"case_title": _LONG_RULE + " from the model", "case_description": "d"}],
    ids=["bound", "from the model"],
)
def test_a_title_over_the_limit_is_cut_and_the_case_opens(
    client: TestClient,  # noqa: F811
    tool_args: Any,
) -> None:
    _seed(client, "INV-LONG-RULE", tool_args=tool_args, rule_name=_LONG_RULE)
    res, grid = _execute_strict(client, "INV-LONG-RULE")
    assert res.json()["status"] == "executed", res.text
    title = grid.created[0]["title"]
    assert len(title.encode()) <= 100
    assert title == _LONG_RULE[:100].rstrip()


def test_the_cut_counts_bytes_and_keeps_whole_characters() -> None:
    from soc_ai.tools.escalate_to_case import fit_case_description, fit_case_title

    # 60 characters of two bytes each after one ASCII letter: 121 bytes.
    cut = fit_case_title("a" + "é" * 60)
    assert cut == "a" + "é" * 49  # 99 bytes. Byte 100 is half a character.
    assert len(cut.encode()) == 99
    assert fit_case_title("  short  ") == "short"
    assert fit_case_title("x" * 100) == "x" * 100
    assert len(fit_case_title("日本語" * 40).encode()) == 99
    assert len(fit_case_description("x" * 1_000_050).encode()) == 1_000_000
    assert fit_case_description("  d  ") == "d"


async def test_the_tool_cuts_the_text_of_every_caller() -> None:
    """The group route and the alert-row route call the tool with their own
    text. The tool is the one place every path passes."""
    from soc_ai.tools.escalate_to_case import escalate_to_case

    grid = _StrictSecurityOnion()
    result = await escalate_to_case(_ALERT, _LONG_RULE, "d" * 1_000_050, auth=grid)
    assert result["case_id"] == "case-77"
    assert len(grid.created[0]["title"].encode()) <= 100
    assert len(grid.created[0]["description"].encode()) == 1_000_000


async def test_the_group_escalate_cuts_its_title() -> None:
    from types import SimpleNamespace

    from soc_ai.api.webui.routes_alert_actions import _escalate_many

    grid = _StrictSecurityOnion()
    state = SimpleNamespace(auth=grid, settings=None, audit=None)
    request = SimpleNamespace(app=SimpleNamespace(state=state))
    event = SimpleNamespace(es_id=_ALERT, src="10.0.0.1", dst="10.0.0.2")
    escalated, failed, case_ids, _empty = await _escalate_many(
        request,  # type: ignore[arg-type]
        [event],
        rule_name=_LONG_RULE,
        session_id="s",
        caller="ana",
    )
    assert (escalated, failed, case_ids) == (1, 0, {_ALERT: "case-77"})
    assert len(grid.created[0]["title"].encode()) <= 100


def test_the_override_path_cuts_its_title() -> None:
    from soc_ai.api.webui.routes_actions import _override_actions

    actions = _override_actions("true_positive", user="ana", rule_name=_LONG_RULE, headline="h")
    assert len(actions[0]["tool_args"]["case_title"].encode()) <= 100
