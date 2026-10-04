"""The osquery result fields are queryable, and their values stay masked at egress.

A Linux host with Elastic Agent and no Elastic Defend ships its process,
login and cron facts as ``osquery_manager.result`` documents. The columns sit
under ``osquery.*``, the query identity under ``action_id`` and ``pack_id``,
and the run metadata under ``osquery_meta.*`` and ``action_data.*``. None of
them passed the OQL whitelist, so the model could neither filter nor group
the one host plane such a host has.

The egress half needs no new rule: the Oracle backstop masks a free-form
value on a field it does not know. The last test pins that, on the path a
new prefix could open.
"""

from __future__ import annotations

import pytest
from soc_ai.oracle.backstop import mask_unclassified_scalars
from soc_ai.oracle.redact import Mapping, sanitize_case
from soc_ai.so_client.oql import FieldWhitelist, parse_oql, validate_oql


@pytest.mark.parametrize(
    "field",
    [
        "osquery.name",
        "osquery.cmdline",
        "osquery.path",
        "osquery.pid",
        "osquery.username",
        "osquery.command",
        "osquery.remote_address",
        "osquery_meta.type",
        "osquery_meta.counter",
        "action_id",
        "action_data.query",
        "action_data.id",
        "pack_id",
        "response_id",
    ],
)
def test_osquery_result_fields_pass_the_whitelist(field: str) -> None:
    assert FieldWhitelist.from_file().is_allowed(field)


@pytest.mark.parametrize("field", ["osqueryx.name", "action_idx", "pack", "osquery_metadata.x"])
def test_lookalike_fields_stay_rejected(field: str) -> None:
    assert not FieldWhitelist.from_file().is_allowed(field)


def test_an_osquery_hunt_query_validates() -> None:
    ast = parse_oql(
        "event.dataset:osquery_manager.result AND action_id:pack_default--baseline_crontab "
        "| groupby osquery.command"
    )
    validate_oql(ast)


def test_an_osquery_value_is_masked_at_the_oracle_boundary() -> None:
    case = {
        "event": {"dataset": "osquery_manager.result"},
        "osquery": {"username": "svc-backup", "command": "run-backup --nightly"},
    }
    sanitized = sanitize_case(case, Mapping())
    masked, count = mask_unclassified_scalars(sanitized, suffixes=(".example.test",))
    assert masked["osquery"]["username"] != "svc-backup"
    assert count >= 1
