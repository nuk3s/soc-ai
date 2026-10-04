"""The prompts name host logs and osquery as host telemetry.

The hunt prompt, the inventory header and the OQL primer defined host
telemetry as endpoint, windows and sysmon. A Linux host that ships system
logs and osquery through Elastic Agent and no Elastic Defend then read as a
host with no host telemetry, and the hunt schema told the model that a
missing dataset is ALWAYS a visibility gap. These tests pin the replacement
rule: a dataset that a host does not ship is a gap in that plane only.
"""

from __future__ import annotations

import json

from soc_ai.agent.hunt import HUNT_SYSTEM_PROMPT, HuntFinding
from soc_ai.agent.prompts import oql_primer_block
from soc_ai.so_client.inventory import DatasetInfo, GridInventory, format_inventory_block

_RULE = "a gap in that plane only"


def _category_description() -> str:
    schema = HuntFinding.model_json_schema()
    return str(schema["properties"]["category"]["description"])


def test_the_hunt_schema_has_the_plane_rule() -> None:
    text = _category_description()
    assert "ALWAYS 'visibility_gap'" not in text
    assert "A dataset that this host does not ship is a gap in that plane only." in text
    assert "Read the host's coverage before you report a host gap." in text


def test_the_hunt_prompt_names_host_logs_and_osquery_as_host_telemetry() -> None:
    prompt = HUNT_SYSTEM_PROMPT
    assert "host logs" in prompt
    assert "osquery" in prompt
    assert "system.auth" in prompt
    assert _RULE in prompt
    # The old definition, which left a Linux agent out of host telemetry.
    assert "A host-logging grid also has endpoint, windows, sysmon and" not in prompt


def test_the_inventory_header_names_host_logs_and_osquery() -> None:
    inv = GridInventory(
        datasets=(
            DatasetInfo(dataset="system.auth", live_count=11309, last_seen_ms=None, categories=()),
        ),
        window_minutes=1440,
        live_events=11309,
    )
    block = format_inventory_block(inv)
    assert "host logs" in block
    assert "osquery" in block
    assert "endpoint/windows/sysmon/etc." not in block
    assert _RULE in block


def test_the_primer_resolves_a_hosts_coverage_in_both_flavors() -> None:
    for flavor in ("triage", "hunt"):
        primer = oql_primer_block(flavor)
        assert "host.name:<name> | groupby event.dataset" in primer, flavor
        assert _RULE in primer, flavor


def test_the_schema_text_survives_json() -> None:
    # The schema reaches the model as JSON. The rule must not depend on markup.
    assert _RULE in json.dumps(HuntFinding.model_json_schema())


def test_the_chat_playbook_reads_host_documents_and_coverage() -> None:
    from soc_ai.agent.chat_agent import _INTERNAL_HOST_PLAYBOOK as playbook

    assert "host.ip:<IP>" in playbook
    assert "t_host_dossier" in playbook
    assert "host.name:<name> | groupby event.dataset" in playbook
    assert _RULE in playbook
    # The old recipe read flows only: an agent's own documents carry host.ip,
    # not source.ip or destination.ip, so they never matched.
    assert "with `source.ip:<IP> OR destination.ip:<IP>` to find every event" not in playbook
