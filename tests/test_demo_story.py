"""The demo story (scripts/demo/build_story.py) and the fixture file it writes.

These keep the public demo from going stale or leaking. The committed
``soc_ai/demo/fixtures.json`` must be exactly what the builder writes from
``scripts/demo/recorded_runs.json`` and ``scripts/demo/story.py``, every
internal address in it must be a machine of the story's estate, no sanitized
label may survive, and the time windows the console opens on must hold data
on any day the demo boots.
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from scripts.demo import build_story
from scripts.demo import story as st
from soc_ai.demo.fixtures import DEFAULT_FIXTURES, load_fixtures, rebase_document

REPO = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(
    not (REPO / "scripts/build-public-mirror.sh").exists(),
    reason="mirror build script not in this tree (public clone): no leak-pattern source",
)


@pytest.fixture(scope="module")
def committed() -> str:
    return DEFAULT_FIXTURES.read_text()


@pytest.fixture(scope="module")
def built() -> str:
    return build_story.render(build_story.build())


def _strings(node: Any) -> list[str]:
    out: list[str] = []
    build_story._raw_strings(node, out)
    return out


def test_the_committed_file_is_what_the_builder_writes(committed: str, built: str) -> None:
    """A change to the story or to the recorded runs needs a rebuild. Run
    ``scripts/demo/build_story.py`` and commit the file it writes."""
    assert committed == built


def test_the_builder_leak_gate_is_clean(committed: str) -> None:
    assert build_story.gate(json.loads(committed), committed) == []


def test_no_sanitized_label_survives(committed: str) -> None:
    assert re.findall(r"\b(?:IP|HOST)_\d+\b", committed) == []


def test_every_internal_address_is_a_machine_of_the_estate(committed: str) -> None:
    estate = {m.ip for m in st.MACHINES} | {"10.20.0.0"}
    found: set[str] = set()
    for text in _strings(json.loads(committed)):
        for raw in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
            try:
                addr = ipaddress.ip_address(raw)
            except ValueError:
                continue
            if addr.is_private and not any(
                addr in ipaddress.ip_network(n)
                for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
            ):
                found.add(raw)
    assert found <= estate, sorted(found - estate)


@pytest.mark.parametrize(
    "parts",
    [
        # Assembled from fragments, so this file passes the mirror scan itself.
        ("10", "9", "8", ""),
        ("10", "1", ""),
        ("10", "99", "0", ""),
        ("192", "168", "1", ""),
    ],
)
def test_no_lab_network_appears(committed: str, parts: tuple[str, ...]) -> None:
    assert ".".join(parts) not in committed


def test_no_lab_host_name_appears(committed: str) -> None:
    for name in ("sr-" + "dc01", "range" + ".lab", "home" + ".lan"):
        assert name not in committed


def test_the_file_stays_inside_the_render_budget(committed: str) -> None:
    """The hosted demo runs on 512 MB. The fixture file stays well under 3 MB."""
    assert len(committed.encode()) < 3 * 1024 * 1024


@pytest.mark.parametrize("boot", ["2026-11-03T08:00:00", "2031-02-17T23:30:00"])
def test_the_console_windows_hold_data_on_any_boot_day(boot: str) -> None:
    """The anchor moves to the seed instant, so the last day and the last
    week hold the story whatever day the demo starts."""
    now = datetime.fromisoformat(boot)
    doc = rebase_document(load_fixtures(), now)

    def age(value: str) -> timedelta:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(UTC).replace(tzinfo=None)
        return now - parsed

    runs = [i for i in doc["investigations"] if i.get("started_by") != "backtest"]
    assert sum(age(i["created_at"]) <= timedelta(hours=24) for i in runs) >= 8
    assert all(age(i["created_at"]) >= timedelta(0) for i in runs)
    alerts = [a["_source"]["@timestamp"] for a in doc["alerts"]]
    assert sum(age(t) <= timedelta(hours=24) for t in alerts) >= 20
    assert sum(age(t) <= timedelta(days=7) for t in alerts) >= 60
    gap = doc["tables"]["grid_gaps"][0]
    assert timedelta(0) < age(gap["ended_at"]) < timedelta(hours=24)
    hits = doc["tables"]["entity_observations"]
    assert sum(age(o["born_at"]) <= timedelta(days=7) for o in hits) == len(hits)


def test_leads_cover_every_state_and_their_hunts_agree() -> None:
    doc = load_fixtures()
    leads = {lead["id"]: lead for lead in doc["tables"]["leads"]}
    hunts = {h["id"]: h for h in doc["hunts"]}
    statuses = {lead["status"] for lead in leads.values()}
    assert statuses == {"open", "hunting", "promoted", "dismissed"}
    reasons = {lead.get("dismissed_reason") for lead in leads.values()}
    assert {"known_change", "hunt_clean"} <= reasons
    hunt_states = {hunts[lead["hunt_id"]]["status"] for lead in leads.values() if lead["hunt_id"]}
    assert {"running", "complete"} <= hunt_states
    for lead in leads.values():
        hunt = hunts.get(lead["hunt_id"] or "")
        if hunt is None:
            continue
        assert hunt["lead_id"] == lead["id"]
        assert hunt["kind"] == "lead"
        threats = hunt.get("threat_findings_count")
        if lead["status"] == "promoted":
            assert threats and hunt["findings_total"] == hunt["findings_investigated"] > 0
        if lead.get("dismissed_reason") == "hunt_clean":
            assert threats == 0


def test_observations_point_at_leads_that_exist() -> None:
    doc = load_fixtures()
    leads = {lead["id"] for lead in doc["tables"]["leads"]}
    for obs in doc["tables"]["entity_observations"]:
        assert obs["lead_id"] is None or obs["lead_id"] in leads
