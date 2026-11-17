"""A zero from a field that no document holds is not a zero on the value.

Measured defect (production review 2026-11-12, hunts finding 2). Ten scheduled
hunts ran ``event.dataset:zeek.ssh AND zeek.ssh.auth_success:true``. Each
returned 0, and six reports stated "no successful SSH login". The grid stores
the value in a different field. A ``groupby zeek.ssh.auth_success`` on 6,771
documents returned empty buckets on 2026-11-01.

The query tools now run one count after a zero. The count tells "no document
holds the field" from "no document has the value".
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.tools._field_check import CHECK_FAILED_NOTE, NOT_EVIDENCE
from soc_ai.tools.discover import field_values
from soc_ai.tools.query_events import query_events_oql

_ZERO: dict[str, Any] = {"took": 1, "hits": {"total": {"value": 0}, "hits": []}}


def _elastic(settings: Settings, responses: list[Any]) -> tuple[ElasticClient, AsyncMock]:
    fake_es = AsyncMock()
    fake_es.search.side_effect = responses
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        return ElasticClient(settings), fake_es


def _check(counts: dict[str, int]) -> dict[str, Any]:
    """The answer of the field check: one doc_count for each named filter."""
    return {
        "took": 1,
        "hits": {"hits": []},
        "aggregations": {
            "field_check": {"buckets": {key: {"doc_count": n} for key, n in counts.items()}}
        },
    }


def _check_body(fake_es: AsyncMock) -> dict[str, Any]:
    return fake_es.search.call_args_list[1].kwargs["body"]  # type: ignore[no-any-return]


def _exists_fields(body: dict[str, Any]) -> dict[str, str]:
    named = body["aggs"]["field_check"]["filters"]["filters"]
    return {key: clause["exists"]["field"] for key, clause in named.items() if "exists" in clause}


# ---------------------------------------------------------------------------
# t_query_events_oql: a filter on a field
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_zero_hit_filter_on_an_absent_field_returns_a_note(
    settings_kratos: Settings,
) -> None:
    """The measured query. No zeek.ssh document holds any name of the field."""
    elastic, _fake_es = _elastic(
        settings_kratos, [_ZERO, _check({"scope": 6771, "f0_0": 0, "f0_1": 0, "f0_2": 0})]
    )
    result = await query_events_oql(
        "event.dataset:zeek.ssh AND zeek.ssh.auth_success:true",
        elastic=elastic,
        settings=settings_kratos,
    )
    assert result.total == 0
    note = result.field_note
    assert note is not None
    assert "`zeek.ssh.auth_success`" in note
    assert "`zeek.ssh`" in note
    assert NOT_EVIDENCE in note
    assert "t_describe_dataset" in note
    # The note reaches the model: it is in the dumped tool result.
    assert result.model_dump(mode="json")["field_note"] == note


@pytest.mark.asyncio
async def test_the_check_is_one_count_in_the_same_dataset_and_window(
    settings_kratos: Settings,
) -> None:
    elastic, fake_es = _elastic(
        settings_kratos, [_ZERO, _check({"scope": 10, "f0_0": 0, "f0_1": 0, "f0_2": 0})]
    )
    await query_events_oql(
        "event.dataset:zeek.ssh AND zeek.ssh.auth_success:true",
        elastic=elastic,
        settings=settings_kratos,
        time_range_minutes=4320,
    )
    assert fake_es.search.call_count == 2
    first = fake_es.search.call_args_list[0].kwargs["body"]
    body = _check_body(fake_es)
    assert body["size"] == 0
    assert body["track_total_hits"] is False
    scope = body["query"]["bool"]["filter"]
    # The same window as the query.
    assert scope[0] == first["query"]["bool"]["filter"][0]
    assert scope[0]["range"]["@timestamp"]["gte"] == "now-4320m"
    # The same dataset as the query, under both dataset name fields.
    assert scope[1] == first["query"]["bool"]["must"][0]["bool"]["must"][0]
    assert {"term": {"event.dataset": "zeek.ssh"}} in scope[1]["bool"]["should"]
    assert {"term": {"data_stream.dataset": "zeek.ssh"}} in scope[1]["bool"]["should"]
    # The same synth exclusion as the query.
    assert body["query"]["bool"]["must_not"] == first["query"]["bool"]["must_not"]
    # Every name of the field, because the query matched every name.
    assert set(_exists_fields(body).values()) == {
        "ssh.authentication.success",
        "ssh.auth_success",
        "zeek.ssh.auth_success",
    }


@pytest.mark.asyncio
async def test_zero_hit_filter_on_a_present_field_returns_no_note(
    settings_kratos: Settings,
) -> None:
    """Negative control: a zero on a value stays a clean zero.

    The grid holds the field, and no document has the value. That zero is
    evidence, and the result must not say that it is not.
    """
    elastic, fake_es = _elastic(
        settings_kratos, [_ZERO, _check({"scope": 6771, "f0_0": 6771, "f0_1": 0, "f0_2": 0})]
    )
    result = await query_events_oql(
        "event.dataset:zeek.ssh AND ssh.authentication.success:true",
        elastic=elastic,
        settings=settings_kratos,
    )
    assert result.total == 0
    assert result.field_note is None
    assert fake_es.search.call_count == 2


@pytest.mark.asyncio
async def test_a_result_with_hits_runs_no_check(settings_kratos: Settings) -> None:
    """Negative control: the cost is zero for a query that matched."""
    hit = {"took": 1, "hits": {"total": {"value": 1}, "hits": [{"_id": "a", "_source": {}}]}}
    elastic, fake_es = _elastic(settings_kratos, [hit])
    result = await query_events_oql(
        "event.dataset:zeek.ssh AND zeek.ssh.auth_success:true",
        elastic=elastic,
        settings=settings_kratos,
    )
    assert result.field_note is None
    assert fake_es.search.call_count == 1


@pytest.mark.asyncio
async def test_zero_hit_query_with_only_a_dataset_filter_runs_no_check(
    settings_kratos: Settings,
) -> None:
    """Negative control: a dataset filter names no field to check."""
    elastic, fake_es = _elastic(settings_kratos, [_ZERO])
    result = await query_events_oql(
        "event.dataset:zeek.smb_files", elastic=elastic, settings=settings_kratos
    )
    assert result.field_note is None
    assert fake_es.search.call_count == 1


@pytest.mark.asyncio
async def test_several_absent_fields_cost_one_count(settings_kratos: Settings) -> None:
    elastic, fake_es = _elastic(
        settings_kratos,
        [_ZERO, _check({"scope": 50, "f0_0": 0, "f1_0": 50, "f2_0": 0})],
    )
    result = await query_events_oql(
        "event.dataset:zeek.conn AND network.direction:outbound AND host.name:web01 "
        "AND source.ip:192.0.2.7",
        elastic=elastic,
        settings=settings_kratos,
    )
    assert fake_es.search.call_count == 2
    assert _exists_fields(_check_body(fake_es)) == {
        "f0_0": "host.name",
        "f1_0": "network.direction",
        "f2_0": "source.ip",
    }
    note = result.field_note or ""
    assert "`host.name` and `source.ip`" in note
    assert "network.direction" not in note


@pytest.mark.asyncio
async def test_a_negated_field_is_not_checked(settings_kratos: Settings) -> None:
    """Negative control: NOT on an absent field matches every document.

    That field cannot cause a zero, so a note that names it is false.
    """
    elastic, fake_es = _elastic(settings_kratos, [_ZERO, _check({"scope": 5, "f0_0": 5})])
    result = await query_events_oql(
        "source.ip:192.0.2.7 AND NOT zeek.ssh.auth_success:true",
        elastic=elastic,
        settings=settings_kratos,
    )
    assert _exists_fields(_check_body(fake_es)) == {"f0_0": "source.ip"}
    assert result.field_note is None


@pytest.mark.asyncio
async def test_an_absent_dataset_says_that_the_grid_holds_no_such_log(
    settings_kratos: Settings,
) -> None:
    elastic, _fake_es = _elastic(settings_kratos, [_ZERO, _check({"scope": 0, "f0_0": 0})])
    result = await query_events_oql(
        "event.dataset:zeek.smb_files AND file.name:PSEXESVC*",
        elastic=elastic,
        settings=settings_kratos,
    )
    note = result.field_note or ""
    assert "No document of `zeek.smb_files` is in this window." in note
    assert NOT_EVIDENCE in note
    assert "Do not report that the activity did not occur." in note


@pytest.mark.asyncio
async def test_a_failed_check_does_not_fail_the_query_and_marks_the_zero(
    settings_kratos: Settings,
) -> None:
    """An unconfirmed zero must not read as a confirmed zero."""
    elastic, fake_es = _elastic(settings_kratos, [_ZERO, RuntimeError("grid refused")])
    result = await query_events_oql(
        "event.dataset:zeek.ssh AND ssh.authentication.success:true",
        elastic=elastic,
        settings=settings_kratos,
    )
    assert result.total == 0
    assert result.field_note == CHECK_FAILED_NOTE
    assert fake_es.search.call_count == 2


# ---------------------------------------------------------------------------
# t_query_events_oql: a groupby on a field
# ---------------------------------------------------------------------------


def _grouped(total: int, agg: str, buckets: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "took": 1,
        "hits": {"total": {"value": total}, "hits": []},
        "aggregations": {agg: {"buckets": buckets}},
    }


@pytest.mark.asyncio
async def test_groupby_on_an_absent_field_names_the_field_that_holds_the_value(
    settings_kratos: Settings,
) -> None:
    """The query matched 6,771 documents and the groupby returned no bucket."""
    elastic, fake_es = _elastic(
        settings_kratos,
        [
            _grouped(6771, "by_zeek_ssh_auth_success", []),
            _check({"scope": 6771, "f0_0": 6771, "f0_1": 0, "f0_2": 0}),
        ],
    )
    result = await query_events_oql(
        "event.dataset:zeek.ssh | groupby zeek.ssh.auth_success",
        elastic=elastic,
        settings=settings_kratos,
    )
    assert result.total == 6771
    note = result.field_note or ""
    assert "`zeek.ssh.auth_success`" in note
    assert "the groupby has no bucket" in note
    assert "Run the groupby on `ssh.authentication.success`." in note
    assert NOT_EVIDENCE in note
    assert fake_es.search.call_count == 2


@pytest.mark.asyncio
async def test_groupby_with_buckets_runs_no_check(settings_kratos: Settings) -> None:
    """Negative control: a groupby that returned a bucket pays nothing."""
    elastic, fake_es = _elastic(
        settings_kratos,
        [_grouped(9, "by_ssh_authentication_success", [{"key": "true", "doc_count": 9}])],
    )
    result = await query_events_oql(
        "event.dataset:zeek.ssh | groupby ssh.authentication.success",
        elastic=elastic,
        settings=settings_kratos,
    )
    assert result.field_note is None
    assert fake_es.search.call_count == 1


@pytest.mark.asyncio
async def test_groupby_on_a_present_field_with_no_match_returns_no_note(
    settings_kratos: Settings,
) -> None:
    """Negative control: the filter matched nothing and both fields are present."""
    elastic, _fake_es = _elastic(
        settings_kratos,
        [_grouped(0, "by_destination_ip", []), _check({"scope": 80, "f0_0": 80, "f1_0": 80})],
    )
    result = await query_events_oql(
        "event.dataset:zeek.conn AND source.ip:192.0.2.7 | groupby destination.ip",
        elastic=elastic,
        settings=settings_kratos,
    )
    assert result.field_note is None


# ---------------------------------------------------------------------------
# t_field_values
# ---------------------------------------------------------------------------


def _values(buckets: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "took": 1,
        "hits": {"total": {"value": 0}, "hits": []},
        "aggregations": {"vals": {"buckets": buckets}},
    }


@pytest.mark.asyncio
async def test_field_values_of_an_absent_field_returns_a_note(settings_kratos: Settings) -> None:
    elastic, fake_es = _elastic(
        settings_kratos, [_values([]), _check({"scope": 900, "f0_0": 900, "f0_1": 0, "f0_2": 0})]
    )
    out = await field_values(
        "zeek.ssh.auth_success", elastic=elastic, settings=settings_kratos, dataset="zeek.ssh"
    )
    assert out["values"] == []
    assert "`zeek.ssh.auth_success`" in out["note"]
    assert "`ssh.authentication.success`" in out["note"]
    assert NOT_EVIDENCE in out["note"]
    assert fake_es.search.call_count == 2
    first = fake_es.search.call_args_list[0].kwargs["body"]
    assert _check_body(fake_es)["query"]["bool"]["filter"] == first["query"]["bool"]["filter"]


@pytest.mark.asyncio
async def test_field_values_with_values_runs_no_check(settings_kratos: Settings) -> None:
    """Negative control."""
    elastic, fake_es = _elastic(settings_kratos, [_values([{"key": "true", "doc_count": 3}])])
    out = await field_values(
        "ssh.authentication.success",
        elastic=elastic,
        settings=settings_kratos,
        dataset="zeek.ssh",
    )
    assert "note" not in out
    assert fake_es.search.call_count == 1


def test_the_primer_states_the_zero_hit_rule() -> None:
    from pathlib import Path

    primer = (Path(__file__).resolve().parents[1] / "docs" / "OQL_PRIMER.md").read_text(
        encoding="utf-8"
    )
    assert "## Zero-hit results" in primer
    assert "`field_note`" in primer
    assert "not evidence of absence" in primer


# ---------------------------------------------------------------------------
# Review of 2026-11-13: defects 8 and 9
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_check_tests_the_names_that_the_query_tested(settings_kratos: Settings) -> None:
    """A Suricata alert holds tags:alert and no event.kind.

    The query widened ``event.kind:alert`` to both alert labels, so it did test
    the tagged alerts. The check read ``event.kind`` alone and called a valid
    zero "cannot match".
    """
    elastic, fake_es = _elastic(
        settings_kratos, [_ZERO, _check({"scope": 500, "f0_0": 500, "f0_1": 0, "f1_0": 500})]
    )
    result = await query_events_oql(
        "event.dataset:suricata.alert AND event.kind:alert AND source.ip:192.0.2.9",
        elastic=elastic,
        settings=settings_kratos,
    )
    assert _exists_fields(_check_body(fake_es)) == {
        "f0_0": "tags",
        "f0_1": "event.kind",
        "f1_0": "source.ip",
    }
    assert result.field_note is None


@pytest.mark.asyncio
async def test_a_label_that_no_document_holds_under_either_name_still_gets_a_note(
    settings_kratos: Settings,
) -> None:
    """Negative control: the wider test must still find an absent field."""
    elastic, _fake_es = _elastic(
        settings_kratos, [_ZERO, _check({"scope": 500, "f0_0": 0, "f0_1": 0, "f1_0": 500})]
    )
    result = await query_events_oql(
        "event.dataset:zeek.conn AND event.kind:alert AND source.ip:192.0.2.9",
        elastic=elastic,
        settings=settings_kratos,
    )
    note = result.field_note or ""
    assert "`event.kind`" in note and NOT_EVIDENCE in note
    assert "source.ip" not in note


@pytest.mark.asyncio
async def test_a_term_that_stayed_as_written_is_checked_as_written(
    settings_kratos: Settings,
) -> None:
    """A filter that names both labels is not widened, so each label is its own field."""
    elastic, fake_es = _elastic(settings_kratos, [_ZERO, _check({"scope": 9, "f0_0": 0})])
    result = await query_events_oql(
        "event.kind:alert AND NOT tags:alert", elastic=elastic, settings=settings_kratos
    )
    assert _exists_fields(_check_body(fake_es)) == {"f0_0": "event.kind"}
    assert "`event.kind`" in (result.field_note or "")


@pytest.mark.asyncio
async def test_the_scope_reads_both_dataset_name_fields(settings_kratos: Settings) -> None:
    """A data stream names its dataset in data_stream.dataset only.

    The scope read event.dataset alone, counted zero and said "The grid holds
    no document of that dataset".
    """
    elastic, fake_es = _elastic(settings_kratos, [_ZERO, _check({"scope": 300, "f0_0": 300})])
    result = await query_events_oql(
        "event.dataset:network_traffic.dns AND dns.question.name:example.org",
        elastic=elastic,
        settings=settings_kratos,
    )
    scope = json.dumps(_check_body(fake_es)["query"]["bool"]["filter"])
    assert '{"term": {"event.dataset": "network_traffic.dns"}}' in scope
    assert '{"term": {"data_stream.dataset": "network_traffic.dns"}}' in scope
    assert result.field_note is None


@pytest.mark.asyncio
async def test_the_scope_knows_both_names_of_the_file_log(settings_kratos: Settings) -> None:
    elastic, fake_es = _elastic(settings_kratos, [_ZERO, _check({"scope": 40, "f0_0": 40})])
    await query_events_oql(
        "event.dataset:zeek.files AND file.mime_type:application/x-dosexec",
        elastic=elastic,
        settings=settings_kratos,
    )
    scope = json.dumps(_check_body(fake_es)["query"]["bool"]["filter"])
    for name in ("zeek.file", "zeek.files"):
        assert f'{{"term": {{"event.dataset": "{name}"}}}}' in scope
        assert f'{{"term": {{"data_stream.dataset": "{name}"}}}}' in scope


@pytest.mark.asyncio
async def test_field_values_reads_the_file_log_under_both_names(settings_kratos: Settings) -> None:
    """t_field_values(dataset="zeek.files") said that the grid holds no such dataset."""
    elastic, fake_es = _elastic(
        settings_kratos, [_values([]), _check({"scope": 40, "f0_0": 0, "f0_1": 0, "f0_2": 0})]
    )
    out = await field_values(
        "zeek.files.md5", elastic=elastic, settings=settings_kratos, dataset="zeek.files"
    )
    for call in fake_es.search.call_args_list:
        body = json.dumps(call.kwargs["body"]["query"])
        assert '{"term": {"event.dataset": "zeek.file"}}' in body
        assert '{"term": {"data_stream.dataset": "zeek.file"}}' in body
    assert "`zeek.files.md5`" in out["note"]


@pytest.mark.asyncio
async def test_field_values_gives_one_note_for_both_causes_of_an_absent_field(
    settings_kratos: Settings,
) -> None:
    """The marker guard runs no search, so its note cannot depend on the dataset count."""
    notes = []
    for scope in (0, 700):
        elastic, _fake_es = _elastic(
            settings_kratos, [_values([]), _check({"scope": scope, "f0_0": 0})]
        )
        out = await field_values(
            "zeek.nope", elastic=elastic, settings=settings_kratos, dataset="zeek.quiet"
        )
        notes.append(out["note"])
    assert notes[0] == notes[1]
    assert "No document of `zeek.quiet` in this window holds the field `zeek.nope`" in notes[0]
    assert NOT_EVIDENCE in notes[0]


def test_the_dataset_filter_of_a_dataset_with_one_name_is_unchanged() -> None:
    """Negative control."""
    from soc_ai.so_client.fields import dataset_name_filter

    assert dataset_name_filter("zeek.conn") == {
        "bool": {
            "should": [
                {"term": {"event.dataset": "zeek.conn"}},
                {"term": {"data_stream.dataset": "zeek.conn"}},
            ],
            "minimum_should_match": 1,
        }
    }
