"""A true positive on a hunt finding opens a case from the finding (review 2026-11-13, D2).

Run 01M78HHDFA7Z0W8Q0PJAMEYG5Y on production: a hunt finding with the verdict
true positive and the headline "a working exploit chain against 10.20.30.164".
The card said "1 action waits for you". Escalate was off: "A promoted finding
has no Security Onion alert to act on." The needs-you count did not hold the
run. The analyst could not open a case from the console.

A finding is no alert, and Security Onion creates a case with no alert on it.
Escalate on a finding run now opens a case from the stored finding. The title
is the title of the finding. The description holds the headline of the run,
the hosts and the cited documents. The alerts among the cited documents are
attached. No argument of the model reaches the write.

The tests use a Security Onion double and a grid double. No test writes to a
live grid.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient
from soc_ai.api.webui import action_rules
from soc_ai.api.webui.action_rules import ActionFacts, action_block
from soc_ai.errors import SoApiError
from soc_ai.tools.escalate_to_case import open_finding_case
from soc_ai.tools.write_exec import FINDING_CASE_TOOL, WRITE_TOOLS, execute_write_tool

from tests.anchor_grid import install
from tests.test_escalate_dedup import _hold, _ledger
from tests.test_needs_you_count import client  # noqa: F401 - the shared fixture
from tests.test_pending_action_rows import _pending_rows

_HUNT = "HUNT-0001"
_TITLE = "LFI on 10.20.30.164 leaks /proc/self/maps with HTTP 200"
_HEADLINE = "The confirmed 200 responses show a working exploit chain against 10.20.30.164."
_HOSTS = ["10.40.50.226", "10.20.30.164"]
# Three Zeek records and one alert, in the order the finding cites them.
_ZEEK = ["nXgxzKEBLWkWRQIwyfAW", "-X5mzKEBLWkWRQIw6KG1", "sH5nzKEBLWkWRQIwNqoT"]
_CITED_ALERT = "8IKUzKEBLWkWRQIwPbm-"
_CITED = [*_ZEEK, _CITED_ALERT]

# What the model wrote on the production run, with one more key planted: a
# list of alerts to attach.
_MODEL_ARGS = {
    "alert_id": "ATTACKER-CHOSEN-ALERT-01",
    "case_title": "MODEL TITLE",
    "case_description": "MODEL DESCRIPTION",
    "alert_ids": ["ATTACKER-CHOSEN-ALERT-02"],
}
_ESCALATE = {
    "tool_name": "escalate_to_case",
    "tool_args": _MODEL_ARGS,
    "rationale": _HEADLINE,
}
_ACK = {"tool_name": "ack_alert", "tool_args": {}, "rationale": "Close it."}
# The cited alert as the grid stores it: on the two hosts of the finding, and
# with no decision in Security Onion.
_ON_HOST = {"source": {"ip": "10.40.50.226"}, "destination": {"ip": "10.20.30.164"}}
_SCOPE_ONE = (
    "Open one Security Onion case for this finding. soc-ai attaches 1 alert that the "
    "finding cites. Security Onion marks each attached alert escalated and acknowledged."
)


class _Response:
    def __init__(self, body: dict[str, Any], status_code: int = 200) -> None:
        self.status_code = status_code
        self._body = body
        self.text = str(body)

    def json(self) -> dict[str, Any]:
        return self._body


class _SecurityOnion:
    """Records each write. ``on_grid`` holds the alerts an attach can find."""

    def __init__(
        self,
        *,
        on_grid: set[str] | None = None,
        create_status: int = 200,
        case_id: str | None = "case-91",
        attach_raises: bool = False,
    ) -> None:
        self.on_grid = on_grid
        self.create_status = create_status
        self.case_id = case_id
        self.attach_raises = attach_raises
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def request(self, method: str, url: str, **kwargs: Any) -> _Response:
        body = dict(kwargs.get("json") or {})
        self.calls.append((url, body))
        if url == "/api/case/":
            if self.create_status >= 400:
                return _Response({"error": "refused"}, self.create_status)
            return _Response({"id": self.case_id} if self.case_id else {})
        if url == "/api/case/events":
            if self.attach_raises:
                raise httpx.ConnectError("the grid went away")
            alert_id = body["fields"]["soc_id"]
            found = self.on_grid is None or alert_id in self.on_grid
            return _Response({"count": 1 if found else 0})
        return _Response({})

    def _bodies(self, url: str) -> list[dict[str, Any]]:
        return [body for called, body in self.calls if called == url]

    @property
    def created(self) -> list[dict[str, Any]]:
        return self._bodies("/api/case/")

    @property
    def attached(self) -> list[str]:
        return [str(b["fields"]["soc_id"]) for b in self._bodies("/api/case/events")]

    @property
    def marked(self) -> list[str]:
        return [str(b["eventFilter"]["soc_id"]) for b in self._bodies("/api/events/ack")]


def _ago(hours: float) -> datetime:
    return (datetime.now(UTC) - timedelta(hours=hours)).replace(tzinfo=None)


def _seed_hunt(client: TestClient, hunt_id: str = _HUNT) -> None:  # noqa: F811
    """A complete hunt with two findings. The run judges the second one."""
    from soc_ai.store.models import Hunt

    findings = [
        {
            "title": "A scan from 10.40.50.58",
            "hosts": ["10.40.50.58"],
            "citations": ["other-doc-000001"],
        },
        {
            "title": _TITLE,
            "detail": "The model wrote a long detail text here.",
            "severity": "high",
            "category": "threat",
            "hosts": _HOSTS,
            # A tool citation and a prose citation are not documents.
            "citations": [*_CITED, "t_host_summary:10.20.30.164", "the pcap ring", _ZEEK[0]],
        },
    ]

    async def go() -> None:
        async with client.app.state.db_sessionmaker() as db:
            db.add(
                Hunt(
                    id=hunt_id,
                    objective="Hunt for malicious activity over 72 hours.",
                    objective_hash="h",
                    started_by="scheduler",
                    kind="scheduled",
                    status="complete",
                    report={"findings": findings},
                )
            )
            await db.commit()

    asyncio.run(go())


def _seed_run(
    client: TestClient,  # noqa: F811
    run_id: str,
    *,
    actions: list[dict[str, Any]] | None = None,
    kind: str = "hunt",
    hunt_id: str | None = _HUNT,
    ordinal: int | None = 1,
    verdict: str = "true_positive",
    hours_ago: float = 1.0,
    events: list[tuple[str, dict[str, Any]]] | None = None,
    started_by: str = "auto-hunt",
) -> None:
    from soc_ai.store.models import Investigation, InvestigationEvent

    subject: dict[str, Any] | None = None
    if kind in ("hunt", "lead"):
        subject = {
            "type": "hunt",
            "hunt_id": hunt_id,
            "finding_titles": [_TITLE],
            "document_ids": [*_ZEEK, "subject-only-doc-0001"],
        }
        if kind == "hunt":
            subject["judges"] = "finding"

    async def go() -> None:
        async with client.app.state.db_sessionmaker() as db:
            db.add(
                Investigation(
                    id=run_id,
                    alert_es_id=_ZEEK[0],
                    kind=kind,
                    hunt_id=hunt_id,
                    finding_ordinal=ordinal,
                    subject_json=subject,
                    rule_name=_TITLE if kind == "hunt" else f"ET TEST {run_id}",
                    status="complete",
                    verdict=verdict,
                    confidence=0.85,
                    rationale=_HEADLINE,
                    report={
                        "verdict": verdict,
                        "recommended_actions": [_ESCALATE] if actions is None else actions,
                    },
                    created_at=_ago(hours_ago),
                    finished_at=_ago(hours_ago),
                    started_by=started_by,
                )
            )
            await db.flush()
            for seq, (event_kind, payload) in enumerate(events or []):
                db.add(
                    InvestigationEvent(
                        investigation_id=run_id, sequence=seq, kind=event_kind, payload=payload
                    )
                )
            await db.commit()

    asyncio.run(go())


def _execute(
    client: TestClient,  # noqa: F811
    run_id: str,
    grid: _SecurityOnion | None = None,
    index: int = 0,
    retry: bool = False,
) -> tuple[Any, _SecurityOnion]:
    grid = grid or _SecurityOnion()

    async def no_case(*_args: Any, **_kwargs: Any) -> dict[str, str]:
        return {}

    with (
        patch.object(client.app.state, "auth", grid),
        patch("soc_ai.api.webui.routes_alert_actions.case_ids_for_alerts", no_case),
    ):
        res = client.post(
            f"/api/v1/investigations/{run_id}/actions/{index}/execute",
            json={"retry": True} if retry else None,
        )
    return res, grid


def _detail(client: TestClient, run_id: str) -> dict[str, Any]:  # noqa: F811
    res = client.get(f"/api/v1/investigations/{run_id}")
    assert res.status_code == 200, res.text
    body: dict[str, Any] = res.json()
    return body


def _needs_you_actions(client: TestClient) -> int:  # noqa: F811
    with patch(
        "soc_ai.api.webui.routes_meta._cached_untriaged_groups",
        AsyncMock(return_value=(0, False)),
    ):
        res = client.get("/api/v1/needs-you")
    assert res.status_code == 200, res.text
    count: int = res.json()["pending_actions"]
    return count


def _setup(client: TestClient, run_id: str = "INV-FINDING", **run: Any) -> None:  # noqa: F811
    """The production shape: a hunt, its finding run, and a grid that holds
    three Zeek records and one alert."""
    install(client, alerts={_CITED_ALERT}, telemetry=set(_ZEEK), sources={_CITED_ALERT: _ON_HOST})
    _seed_hunt(client)
    _seed_run(client, run_id, **run)


# ── The defect ──────────────────────────────────────────────────────────────


def test_escalate_on_a_finding_opens_a_case_from_the_finding(client: TestClient) -> None:  # noqa: F811
    _setup(client)
    res, grid = _execute(client, "INV-FINDING")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["status"] == "executed", body
    assert len(grid.created) == 1
    case = grid.created[0]
    assert case["title"] == _TITLE
    assert case["description"] == (
        f"{_HEADLINE}\n\n"
        "Hosts: 10.40.50.226, 10.20.30.164\n"
        f"Cited documents: {', '.join(_CITED)}\n"
        "Source: soc-ai investigation INV-FINDING of a hunt finding."
    )
    # The alert among the cited documents is on the case. A Zeek record is not.
    assert grid.attached == [_CITED_ALERT]
    assert grid.marked == [_CITED_ALERT]
    assert body["detail"] == (
        "soc-ai created case case-91 from the finding. "
        "1 alert that the finding cites is attached to it."
    )
    assert body["count"] == 1
    assert _ledger(client, _CITED_ALERT) == (True, "case-91")


def test_the_card_the_row_and_the_count_offer_the_escalate(client: TestClient) -> None:  # noqa: F811
    """The page said an action waits, and the count said it does not."""
    _setup(client, actions=[_ESCALATE, _ACK])
    detail = _detail(client, "INV-FINDING")
    assert [a["blockedReason"] for a in detail["actions"]] == [
        None,
        action_rules.PROMOTED_FINDING,
    ]
    assert _needs_you_actions(client) == 1
    rows = _pending_rows(client)
    assert [r["id"] for r in rows] == ["INV-FINDING"]
    assert [
        (a["type"], a["targetType"], a["target"], a["executable"])
        for a in rows[0]["waitingActions"]
    ] == [("escalate", "finding", _TITLE, True)]
    scope = client.get("/api/v1/investigations/INV-FINDING/actions/0/scope").json()
    # The count is the alerts that the press attaches and marks.
    assert (scope["scope"], scope["count"], scope["held"]) == ("finding", 1, 0)
    assert scope["sentence"] == _SCOPE_ONE
    assert scope["cases"] == []


def test_the_executed_escalate_leaves_the_count(client: TestClient) -> None:  # noqa: F811
    _setup(client)
    assert _needs_you_actions(client) == 1
    res, _grid = _execute(client, "INV-FINDING")
    assert res.json()["status"] == "executed", res.text
    assert _needs_you_actions(client) == 0
    action = _detail(client, "INV-FINDING")["actions"][0]
    assert action["applied"] is True
    assert action["appliedDetail"].startswith("soc-ai created case case-91 from the finding.")


def test_a_finding_that_cites_no_alert_opens_a_case_with_no_alert(client: TestClient) -> None:  # noqa: F811
    """Security Onion creates a case from a title and a description alone."""
    install(client, telemetry={*_ZEEK, _CITED_ALERT})
    _seed_hunt(client)
    _seed_run(client, "INV-FINDING")
    res, grid = _execute(client, "INV-FINDING")
    body = res.json()
    assert body["status"] == "executed", body
    assert len(grid.created) == 1
    assert grid.attached == [] and grid.marked == []
    assert body["detail"] == (
        "soc-ai created case case-91 from the finding. "
        "The finding cites no Security Onion alert, so the case holds no alert."
    )
    # A case with no alert is a write. The row reads a count of 0 as no write.
    assert body["count"] == 1


# ── The case content comes from the stored finding ──────────────────────────


def test_no_argument_of_the_model_reaches_the_write(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL (F07). The model names an alert, a title, a
    description and a list of alerts. None of them is in any request."""
    _setup(client)
    res, grid = _execute(client, "INV-FINDING")
    assert res.json()["status"] == "executed", res.text
    sent = str(grid.calls)
    for planted in ("ATTACKER-CHOSEN-ALERT", "MODEL TITLE", "MODEL DESCRIPTION"):
        assert planted not in sent, planted
    # The detail text of the finding is model text too. The case leaves it out.
    assert "long detail text" not in sent
    # A document of the hunt that this finding does not cite stays off the case.
    assert "subject-only-doc-0001" not in sent and "other-doc-000001" not in sent


def test_a_report_cannot_name_the_finding_case_tool(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL on the path the guard would miss. The tool takes a
    list of alerts. A stored action that names the tool must not run it, on a
    finding run or on an alert run."""
    planted = {
        "tool_name": FINDING_CASE_TOOL,
        "tool_args": {"case_title": "t", "case_description": "d", "alert_ids": [_CITED_ALERT]},
        "rationale": "Open it.",
    }
    _setup(client, actions=[planted])
    _seed_run(client, "INV-ALERT", actions=[planted], kind="suricata", hunt_id=None, ordinal=None)
    assert FINDING_CASE_TOOL not in WRITE_TOOLS
    for run_id in ("INV-FINDING", "INV-ALERT"):
        res, grid = _execute(client, run_id)
        assert res.status_code == 400, res.text
        assert res.json()["detail"]["reason"] == "not_executable"
        assert grid.calls == []
    assert _needs_you_actions(client) == 0


def test_a_deleted_hunt_leaves_a_case_from_the_record_of_the_run(client: TestClient) -> None:  # noqa: F811
    """The run keeps the title and the documents it read. The link to the
    hunt can dangle, and the case still opens."""
    install(client, alerts={_CITED_ALERT}, telemetry={*_ZEEK, "subject-only-doc-0001"})
    _seed_run(client, "INV-ORPHAN")
    res, grid = _execute(client, "INV-ORPHAN")
    assert res.json()["status"] == "executed", res.text
    case = grid.created[0]
    assert case["title"] == _TITLE
    assert case["description"] == (
        f"{_HEADLINE}\n\n"
        f"Cited documents: {', '.join([*_ZEEK, 'subject-only-doc-0001'])}\n"
        "Source: soc-ai investigation INV-ORPHAN of a hunt finding."
    )
    assert grid.attached == []


# ── One case for one finding ────────────────────────────────────────────────


def test_a_second_press_opens_no_second_case(client: TestClient) -> None:  # noqa: F811
    _setup(client)
    first, _grid = _execute(client, "INV-FINDING")
    assert first.json()["status"] == "executed"
    second, grid = _execute(client, "INV-FINDING")
    assert second.json()["status"] == "executed"
    assert second.json()["detail"] == "Already executed. soc-ai did not repeat it."
    assert grid.calls == []


def test_a_run_of_the_same_finding_opens_no_second_case(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL on the path the receipt would miss. The receipt of a
    case is on the run that opened it. A Re-run of the finding is a new run
    with no receipt, and its card offers Escalate again."""
    _setup(client, run_id="INV-OLD", hours_ago=5)
    first, _grid = _execute(client, "INV-OLD")
    assert first.json()["status"] == "executed"
    _seed_run(client, "INV-NEW", hours_ago=1)
    second, grid = _execute(client, "INV-NEW")
    body = second.json()
    assert body["status"] == "executed", body
    assert body["detail"] == (
        "This finding is already on Security Onion case case-91. soc-ai opens no second case."
    )
    assert grid.calls == []
    assert body["count"] == 0
    assert _detail(client, "INV-NEW")["actions"][0]["applied"] is True


def test_a_run_of_another_finding_opens_its_own_case(client: TestClient) -> None:  # noqa: F811
    """Control: the rule is one case for one finding, and no wider."""
    _setup(client, run_id="INV-F2")
    _execute(client, "INV-F2")
    _seed_run(client, "INV-F1", ordinal=0)
    res, grid = _execute(client, "INV-F1", _SecurityOnion(case_id="case-92"))
    assert res.json()["status"] == "executed", res.text
    assert [c["title"] for c in grid.created] == ["A scan from 10.40.50.58"]


def test_an_alert_that_is_already_on_a_case_is_not_attached_again(client: TestClient) -> None:  # noqa: F811
    _setup(client)
    _hold(client, _CITED_ALERT, "case-earlier")
    res, grid = _execute(client, "INV-FINDING")
    body = res.json()
    assert body["status"] == "executed", body
    assert len(grid.created) == 1
    assert grid.attached == []
    assert body["detail"] == (
        "soc-ai created case case-91 from the finding. soc-ai attached no alert. "
        "soc-ai skipped 1 alert that the finding cites."
    )
    assert _ledger(client, _CITED_ALERT) == (True, "case-earlier")


# ── What stays refused ──────────────────────────────────────────────────────


def test_an_acknowledge_on_a_finding_stays_refused(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL. A finding has no alert to acknowledge."""
    _setup(client, actions=[_ACK], verdict="false_positive")
    res, grid = _execute(client, "INV-FINDING")
    assert res.status_code == 400, res.text
    assert res.json()["detail"]["reason"] == "hunt_kind_no_so_target"
    assert res.json()["detail"]["hint"] == action_rules.PROMOTED_FINDING
    assert grid.calls == []


def test_a_promoted_lead_stays_refused(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL. A lead run judges a whole hunt. It names no one
    finding to open a case from."""
    _setup(client, run_id="INV-LEAD", kind="lead", ordinal=None)
    res, grid = _execute(client, "INV-LEAD")
    assert res.status_code == 400, res.text
    assert res.json()["detail"]["hint"] == action_rules.PROMOTED_LEAD
    assert grid.calls == []
    assert _needs_you_actions(client) == 0


def test_the_run_level_reason_keeps_the_group_writes_off(client: TestClient) -> None:  # noqa: F811
    """The settled bar acknowledges and escalates the alerts of a rule. A
    finding has no rule, so the page keeps those two writes off."""
    _setup(client)
    assert _detail(client, "INV-FINDING")["writeBlockedReason"] == action_rules.PROMOTED_FINDING
    assert action_block(ActionFacts(promoted="finding"), None) is not None
    assert action_block(ActionFacts(promoted="finding"), "escalate_to_case") is None
    assert action_block(ActionFacts(promoted="finding"), "add_case_comment") is not None
    assert action_block(ActionFacts(promoted="lead"), "escalate_to_case") is not None
    # The other rules still close the finding case.
    assert action_block(ActionFacts(promoted="finding", replay=True), "escalate_to_case")
    assert action_block(ActionFacts(promoted="finding", superseded_by="X"), "escalate_to_case")
    assert action_block(ActionFacts(promoted="finding", demo=True), "escalate_to_case")


def test_a_grid_that_does_not_answer_opens_no_case(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL. soc-ai cannot tell which cited documents are alerts.
    A case opened now would leave the alerts off it, and the receipt would
    close the action. The press can work later."""
    install(client, down=True)
    _seed_hunt(client)
    _seed_run(client, "INV-FINDING")
    res, grid = _execute(client, "INV-FINDING")
    assert res.status_code == 503, res.text
    assert res.json()["detail"]["reason"] == "anchor_unread"
    assert res.json()["detail"]["hint"] == (
        "soc-ai could not read the documents that the finding cites. "
        "Try again when the grid answers."
    )
    assert grid.calls == []
    assert _detail(client, "INV-FINDING")["actions"][0]["applied"] is False


def test_a_refused_create_is_an_error_and_the_card_stays_open(client: TestClient) -> None:  # noqa: F811
    _setup(client)
    res, _grid = _execute(client, "INV-FINDING", _SecurityOnion(create_status=500))
    body = res.json()
    assert body["status"] == "error", body
    assert "open_finding_case returned 500" in body["error"]
    assert _detail(client, "INV-FINDING")["actions"][0]["applied"] is False
    assert _needs_you_actions(client) == 1


def test_an_alert_the_attach_does_not_find_is_named(client: TestClient) -> None:  # noqa: F811
    """The case exists, so the press is done. The sentence states the gap."""
    _setup(client)
    res, grid = _execute(client, "INV-FINDING", _SecurityOnion(on_grid=set()))
    body = res.json()
    assert body["status"] == "executed", body
    assert grid.marked == []
    assert body["detail"] == (
        "soc-ai created case case-91 from the finding. soc-ai attached no alert. "
        "Security Onion did not attach 1 alert that the finding cites."
    )
    # The claim stays open, so the next escalate of that alert asks the grid.
    assert _ledger(client, _CITED_ALERT) == (True, None)


# ── The tool ────────────────────────────────────────────────────────────────


async def test_the_tool_creates_the_case_then_attaches_and_marks_each_alert() -> None:
    grid = _SecurityOnion()
    result = await open_finding_case(
        "  Title  ", "  Description  ", ["alert-aaaa-0001", "alert-bbbb-0002"], auth=grid
    )
    assert [url for url, _body in grid.calls] == [
        "/api/case/",
        "/api/case/events",
        "/api/events/ack",
        "/api/case/events",
        "/api/events/ack",
    ]
    assert grid.created == [{"title": "Title", "description": "Description"}]
    assert result["case_id"] == "case-91"
    assert result["alerts_attached"] == ["alert-aaaa-0001", "alert-bbbb-0002"]
    assert result["alerts_unattached"] == {} and result["alerts_unmarked"] == []


async def test_the_tool_sends_the_request_shapes_of_the_alert_escalate() -> None:
    """One builder for the attach and one for the mark, so the two tools
    cannot send different requests."""
    from soc_ai.tools.escalate_to_case import escalate_to_case

    alert = _SecurityOnion()
    await escalate_to_case("alert-aaaa-0001", "T", "D", auth=alert)
    finding = _SecurityOnion()
    await open_finding_case("T", "D", ["alert-aaaa-0001"], auth=finding)

    def shape(calls: list[tuple[str, dict[str, Any]]]) -> list[tuple[str, dict[str, Any]]]:
        return [(url, {k: v for k, v in body.items() if k != "dateRange"}) for url, body in calls]

    assert shape(finding.calls) == shape(alert.calls)


async def test_the_tool_with_no_alert_makes_one_request() -> None:
    grid = _SecurityOnion()
    result = await open_finding_case("T", "D", auth=grid)
    assert [url for url, _body in grid.calls] == ["/api/case/"]
    assert result["alerts_attached"] == []


async def test_the_tool_never_raises_after_the_case_exists() -> None:
    """A raise makes the caller retry, and the retry opens a second case."""
    grid = _SecurityOnion(attach_raises=True)
    result = await open_finding_case("T", "D", ["alert-aaaa-0001"], auth=grid)
    assert result["case_id"] == "case-91"
    assert result["alerts_attached"] == []
    assert result["alerts_unattached"] == {
        "alert-aaaa-0001": "the attach did not complete (ConnectError)"
    }


async def test_the_tool_refuses_bad_arguments_before_any_request() -> None:
    grid = _SecurityOnion()
    with pytest.raises(ValueError, match="invalid alert id"):
        await open_finding_case("T", "D", ["bad id with spaces"], auth=grid)
    with pytest.raises(ValueError, match="case_title"):
        await open_finding_case("  ", "D", auth=grid)
    with pytest.raises(ValueError, match="case_description"):
        await open_finding_case("T", "", auth=grid)
    assert grid.calls == []


async def test_a_refused_create_raises() -> None:
    with pytest.raises(SoApiError):
        await open_finding_case("T", "D", auth=_SecurityOnion(create_status=403))


async def test_the_audited_path_runs_the_tool_and_records_the_intent() -> None:
    grid = _SecurityOnion()
    audit = AsyncMock()
    result, error = await execute_write_tool(
        FINDING_CASE_TOOL,
        {"case_title": "T", "case_description": "D", "alert_ids": []},
        auth=grid,  # type: ignore[arg-type]
        settings=None,  # type: ignore[arg-type]
        audit=audit,
        user="ana",
    )
    assert error is None and result["case_id"] == "case-91"
    intent = audit.log_kind.await_args_list[0]
    assert intent.args[1] == "tool_call"
    assert intent.args[2]["tool"] == FINDING_CASE_TOOL
    assert intent.kwargs["mutating"] is True


# ── The review of the lane ──────────────────────────────────────────────────
#
# Defect 1: a title over 100 bytes. Defect 2: one finding, two cases, three
# ways. Defect 3: no cap and no statement for the cited alerts. Defect 7: the
# console and the server on what a finding run is.


def _seed_hunt_with(client: TestClient, finding: dict[str, Any]) -> None:  # noqa: F811
    """A hunt whose second finding is ``finding``."""
    from soc_ai.store.models import Hunt

    async def go() -> None:
        async with client.app.state.db_sessionmaker() as db:
            db.add(
                Hunt(
                    id=_HUNT,
                    objective="o",
                    objective_hash="h",
                    started_by="scheduler",
                    kind="scheduled",
                    status="complete",
                    report={"findings": [{"title": "x", "hosts": [], "citations": []}, finding]},
                )
            )
            await db.commit()

    asyncio.run(go())


class _StrictSecurityOnion(_SecurityOnion):
    """The double with the title rule of the upstream source: 100 bytes."""

    async def request(self, method: str, url: str, **kwargs: Any) -> _Response:
        body = dict(kwargs.get("json") or {})
        size = len(str(body.get("title", "")).encode())
        if url == "/api/case/" and size > 100:
            self.calls.append((url, body))
            return _Response({"error": f"title is too long ({size}/100)"}, 400)
        return await super().request(method, url, **kwargs)


def test_a_finding_title_over_the_limit_is_cut_and_the_case_opens(client: TestClient) -> None:  # noqa: F811
    stage = "LFI on 10.20.30.164 leaks /proc/self/maps with HTTP 200 and then a second stage "
    title = (stage * 2)[:118]
    install(client)
    _seed_hunt_with(client, {"title": title, "hosts": ["10.20.30.164"], "citations": []})
    _seed_run(client, "INV-FINDING")
    res, grid = _execute(client, "INV-FINDING", _StrictSecurityOnion())
    assert res.json()["status"] == "executed", res.text
    assert grid.created[0]["title"] == title[:100].rstrip()
    assert _needs_you_actions(client) == 0


def test_two_escalate_actions_of_one_report_open_one_case(client: TestClient) -> None:  # noqa: F811
    """Scenario B. The receipt named one action, and the guard read other runs only."""
    second = {**_ESCALATE, "rationale": "Open a case for the exploit chain."}
    _setup(client, actions=[_ESCALATE, second])
    grid = _SecurityOnion()
    first, _ = _execute(client, "INV-FINDING", grid, index=0)
    again, _ = _execute(client, "INV-FINDING", grid, index=1)
    assert first.json()["status"] == again.json()["status"] == "executed"
    assert len(grid.created) == 1
    assert again.json()["detail"] == (
        "This finding is already on Security Onion case case-91. soc-ai opens no second case."
    )
    assert again.json()["count"] == 0
    assert [a["applied"] for a in _detail(client, "INV-FINDING")["actions"]] == [True, True]
    assert _needs_you_actions(client) == 0


def test_an_override_after_the_case_opens_no_second_case(client: TestClient) -> None:  # noqa: F811
    """Scenario A. The override writes a new action, with a new identity."""
    _setup(client)
    grid = _SecurityOnion()
    first, _ = _execute(client, "INV-FINDING", grid)
    assert first.json()["status"] == "executed"
    ok = client.post(
        "/api/v1/investigations/INV-FINDING/override",
        json={"verdict": "true_positive", "rationale": "confirmed with the owner"},
    )
    assert ok.status_code == 200, ok.text
    # The page offers the new action. The scope states that the press opens no case.
    scope = client.get("/api/v1/investigations/INV-FINDING/actions/0/scope").json()
    assert (scope["count"], scope["sentence"]) == (
        0,
        "This finding is already on Security Onion case case-91. soc-ai opens no second case.",
    )
    again, _ = _execute(client, "INV-FINDING", grid)
    assert again.json()["status"] == "executed", again.text
    assert len(grid.created) == 1
    assert _needs_you_actions(client) == 0


def test_a_press_that_cannot_record_its_intent_opens_no_case(client: TestClient) -> None:  # noqa: F811
    """Scenario C, first half. The store refuses the write, so nothing can
    record the press. No request reaches Security Onion, and the next press
    opens the one case."""
    from soc_ai.api.webui import routes_actions

    _setup(client)
    grid = _SecurityOnion()
    with patch.object(
        routes_actions.inv_svc, "append_events", side_effect=RuntimeError("database is locked")
    ):
        first, _ = _execute(client, "INV-FINDING", grid)
    assert first.json()["status"] == "error"
    assert first.json()["error"] == (
        "soc-ai could not record the press, so it opened no case. Try again."
    )
    assert grid.created == []
    again, _ = _execute(client, "INV-FINDING", grid)
    assert again.json()["status"] == "executed", again.text
    assert len(grid.created) == 1


def test_a_lost_result_opens_no_second_case(client: TestClient) -> None:  # noqa: F811
    """Scenario C. The case exists and the result write fails. The intent is
    on the record with no result, so the next press opens no case. It says
    that a case can exist, and where to look."""
    from soc_ai.api.webui import routes_actions

    _setup(client)
    grid = _SecurityOnion()
    real = routes_actions.inv_svc.append_events
    writes: list[str] = []

    async def lose_the_result(db: Any, inv_id: str, events: list[dict[str, Any]]) -> Any:
        phase = str(events[0]["payload"].get("phase"))
        writes.append(phase)
        if phase == "done":
            raise RuntimeError("database is locked")
        return await real(db, inv_id, events)

    with patch.object(routes_actions.inv_svc, "append_events", lose_the_result):
        first, _ = _execute(client, "INV-FINDING", grid)
    assert writes == ["intent", "done"]
    assert first.json()["status"] == "executed"
    assert len(grid.created) == 1
    assert _detail(client, "INV-FINDING")["actions"][0]["applied"] is False

    expected = (
        "An earlier press started a Security Onion case for this finding, and soc-ai has "
        "no record of the result. A case can exist. soc-ai opens no case. Look in the "
        f'Cases page of Security Onion for the title "{_TITLE}".'
    )
    scope = client.get("/api/v1/investigations/INV-FINDING/actions/0/scope").json()
    assert (scope["count"], scope["sentence"]) == (0, expected)
    again, _ = _execute(client, "INV-FINDING", grid)
    assert again.json()["status"] == "error"
    assert again.json()["error"] == expected
    assert len(grid.created) == 1
    # A later run of the finding meets the same record.
    _seed_run(client, "INV-NEW", hours_ago=0.5)
    later, _ = _execute(client, "INV-NEW", grid)
    assert later.json()["error"] == expected
    assert len(grid.created) == 1


@pytest.mark.parametrize(("status", "retry"), [(400, True), (500, False)])
def test_only_a_create_that_was_refused_lets_the_next_press_run(
    client: TestClient,  # noqa: F811
    status: int,
    retry: bool,
) -> None:
    """A 4xx proves that no case exists. A 5xx can follow a create that took
    effect, so the intent stays open."""
    _setup(client)
    first, _ = _execute(client, "INV-FINDING", _SecurityOnion(create_status=status))
    assert first.json()["status"] == "error"
    assert f"open_finding_case returned {status}" in first.json()["error"]
    again, grid = _execute(client, "INV-FINDING")
    assert (again.json()["status"] == "executed") is retry, again.text
    assert len(grid.created) == (1 if retry else 0)


def test_the_case_attaches_at_most_25_alerts_and_says_so_first(client: TestClient) -> None:  # noqa: F811
    """A finding cites 120 alerts. The scope said "one case" and the press
    sent 120 attach requests and 120 acknowledgements."""
    cited = [f"citedAlert{i:06d}" for i in range(120)]
    install(client, alerts=set(cited), sources=dict.fromkeys(cited, _ON_HOST))
    _seed_hunt_with(client, {"title": "A finding", "hosts": ["10.20.30.164"], "citations": cited})
    _seed_run(client, "INV-FINDING")
    scope = client.get("/api/v1/investigations/INV-FINDING/actions/0/scope").json()
    assert (scope["count"], scope["held"]) == (25, 95)
    assert scope["sentence"] == (
        "Open one Security Onion case for this finding. soc-ai attaches 25 alerts that the "
        "finding cites. Security Onion marks each attached alert escalated and acknowledged. "
        "soc-ai skips 95 alerts that the finding cites. 95 alerts are over the limit of 25."
    )
    res, grid = _execute(client, "INV-FINDING")
    assert grid.attached == cited[:25]
    assert grid.marked == cited[:25]
    assert res.json()["detail"] == (
        "soc-ai created case case-91 from the finding. 25 alerts that the finding cites are "
        "attached to it. soc-ai skipped 95 alerts that the finding cites."
    )


def test_an_alert_with_a_decision_or_on_another_host_is_skipped(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL. An attach also acknowledges the alert, so the case
    takes only an alert with no decision that is on a host of the finding."""
    cited = {
        "alertAcknowledged01": {**_ON_HOST, "event": {"acknowledged": True}},
        "alertEscalated00001": {**_ON_HOST, "event": {"escalated": True}},
        "alertOtherHost00001": {"source": {"ip": "10.1.1.1"}, "destination": {"ip": "10.2.2.2"}},
        "alertNoHostAtAll001": {},
        "alertOnTheLedger001": _ON_HOST,
        "alertByHostName0001": {"host": {"name": "WEB-01"}},
    }
    install(client, alerts=set(cited), sources=cited)
    _hold(client, "alertOnTheLedger001", "case-earlier")
    _seed_hunt_with(
        client,
        {"title": "A finding", "hosts": ["10.20.30.164", "web-01"], "citations": list(cited)},
    )
    _seed_run(client, "INV-FINDING")
    scope = client.get("/api/v1/investigations/INV-FINDING/actions/0/scope").json()
    assert (scope["count"], scope["held"]) == (1, 5)
    assert scope["sentence"].endswith(
        "soc-ai skips 5 alerts that the finding cites. 2 alerts already have a decision. "
        "1 alert is already on a case. 2 alerts are not on a host of the finding."
    )
    res, grid = _execute(client, "INV-FINDING")
    assert grid.attached == ["alertByHostName0001"]
    assert res.json()["detail"] == (
        "soc-ai created case case-91 from the finding. 1 alert that the finding cites is "
        "attached to it. soc-ai skipped 5 alerts that the finding cites."
    )


def test_the_detail_names_the_promotion_for_the_console(client: TestClient) -> None:  # noqa: F811
    """Defect 7. The console read the kind of the run. The server reads the
    promotion. One field now carries the answer of the server."""
    _setup(client)
    _seed_run(client, "INV-LEAD", kind="lead", ordinal=None)
    _seed_run(client, "INV-ALERT", kind="suricata", hunt_id=None, ordinal=None)
    kinds = {
        r: _detail(client, r)["promotedKind"] for r in ("INV-FINDING", "INV-LEAD", "INV-ALERT")
    }
    assert kinds == {"INV-FINDING": "finding", "INV-LEAD": "lead", "INV-ALERT": None}


# ── The one way out of a press with no result ───────────────────────────────
#
# A create that fails with a 5xx leaves the intent open, and each later press
# was refused for good while the finding still counted in Needs you. The
# analyst looks at the Cases page, finds no case with the title, and presses
# "Try again". The press writes an audit record, clears the intent and runs
# the open once more.


def _scope(client: TestClient, run_id: str = "INV-FINDING") -> dict[str, Any]:  # noqa: F811
    body: dict[str, Any] = client.get(f"/api/v1/investigations/{run_id}/actions/0/scope").json()
    return body


def _blocked(client: TestClient) -> None:  # noqa: F811
    """Leave the finding with an intent and no result: the create answers 500."""
    _setup(client)
    first, _grid = _execute(client, "INV-FINDING", _SecurityOnion(create_status=500))
    assert first.json()["status"] == "error"


def test_try_again_clears_the_press_with_no_result_and_opens_one_case(client: TestClient) -> None:  # noqa: F811
    _blocked(client)
    scope = _scope(client)
    assert scope["retry"] is True
    assert scope["retrySentence"] == (
        "Look at the Cases page of Security Onion first. Press Try again only if no case "
        f'has the title "{_TITLE}". soc-ai then opens one case and records your name.'
    )
    # A plain press stays refused.
    plain, grid = _execute(client, "INV-FINDING")
    assert plain.json()["status"] == "error"
    assert grid.created == []

    audit = AsyncMock()
    with patch.object(client.app.state, "audit", audit):
        again, grid = _execute(client, "INV-FINDING", retry=True)
    body = again.json()
    assert body["status"] == "executed", body
    assert len(grid.created) == 1
    assert grid.attached == [_CITED_ALERT]
    # The audit record of the retry comes before the intent of the write.
    records = [call.args[2] for call in audit.log_kind.await_args_list]
    assert records[0]["phase"] == "retry"
    assert records[0]["tool"] == FINDING_CASE_TOOL
    assert records[0]["finding"] == f"hunt:{_HUNT}:1"
    assert records[0]["case_title"] == _TITLE
    assert audit.log_kind.await_args_list[0].kwargs["mutating"] is True
    assert [r["phase"] for r in records[:2]] == ["retry", "intent"]

    after = _scope(client)
    assert (after["retry"], after["count"]) == (False, 0)
    assert "already on Security Onion case case-91" in after["sentence"]
    assert _needs_you_actions(client) == 0


def test_a_recorded_result_offers_no_try_again(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL. The finding has its case on the record. No surface
    offers Try again, and a press that sends it opens no second case."""
    second = {**_ESCALATE, "rationale": "Open a case for the exploit chain."}
    _setup(client, actions=[_ESCALATE, second])
    grid = _SecurityOnion()
    first, _ = _execute(client, "INV-FINDING", grid)
    assert first.json()["status"] == "executed"
    scope = client.get("/api/v1/investigations/INV-FINDING/actions/1/scope").json()
    assert (scope["retry"], scope["retrySentence"]) == (False, None)
    again, _ = _execute(client, "INV-FINDING", grid, index=1, retry=True)
    assert again.json()["detail"] == (
        "This finding is already on Security Onion case case-91. soc-ai opens no second case."
    )
    assert len(grid.created) == 1


def test_a_fresh_finding_offers_no_try_again(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL. No press ran yet. The flag changes nothing: one case."""
    _setup(client)
    assert _scope(client)["retry"] is False
    res, grid = _execute(client, "INV-FINDING", retry=True)
    assert res.json()["status"] == "executed", res.text
    assert len(grid.created) == 1


def test_a_retry_with_no_audit_record_opens_no_case(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL. The audit store refuses the record, so the intent
    stays and no request reaches Security Onion."""
    from soc_ai.audit.logger import AuditWriteError

    _blocked(client)
    audit = AsyncMock()
    audit.log_kind.side_effect = AuditWriteError("the audit store is down")
    with patch.object(client.app.state, "audit", audit):
        res, grid = _execute(client, "INV-FINDING", retry=True)
    assert res.json()["status"] == "error"
    assert res.json()["error"] == (
        "soc-ai could not record the retry, so it opened no case. Try again."
    )
    assert grid.created == []
    assert _scope(client)["retry"] is True


def test_the_row_of_a_blocked_finding_offers_no_escalate(client: TestClient) -> None:  # noqa: F811
    """The pending list row read the record of the press no more than the card
    did. It offered Escalate, and the press only returned the blocked
    sentence. The row now carries ``retry``, and the console links it to the
    investigation, whose card offers Try again."""
    _blocked(client)
    assert _scope(client)["retry"] is True
    rows = _pending_rows(client)
    assert [r["id"] for r in rows] == ["INV-FINDING"]
    assert [(a["type"], a["targetType"], a["retry"]) for a in rows[0]["waitingActions"]] == [
        ("escalate", "finding", True)
    ]


def test_the_row_of_a_fresh_or_settled_finding_carries_no_retry(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL. No press ran: the row offers Escalate. A second
    escalate of a finding with its case on the record waits with no retry."""
    second = {**_ESCALATE, "rationale": "Open a case for the exploit chain."}
    _setup(client, actions=[_ESCALATE, second])
    fresh = _pending_rows(client)
    assert [a["retry"] for a in fresh[0]["waitingActions"]] == [False, False]
    first, _ = _execute(client, "INV-FINDING", _SecurityOnion())
    assert first.json()["status"] == "executed"
    for row in _pending_rows(client):
        assert all(a["retry"] is False for a in row["waitingActions"])
