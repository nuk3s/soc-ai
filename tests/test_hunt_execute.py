"""Running a spec: candidates, and the blind-versus-clean distinction.

The distinction is the reason the precondition exists. "The DCSync spec found
nothing" and "the DCSync spec cannot see, because Directory Service Access
auditing is off on that DC" are opposite facts about your security posture, and
reporting the second as the first is a false all-clear.

Acceptance against the live range, whole catalog through the CLI,
2026-09-03T00:00Z to 2026-09-06T00:00Z, exit 0:

    decoy-opencanary-interaction     precondition 14   matched 6  -> 2 candidates
    identity-4662-dcsync-nonmachine  precondition 47   matched 2  -> localuser
    identity-4768-preauth-disabled   precondition 3914 matched 1  -> svc_legacy
    identity-4769-rc4-service-ticket precondition 4381 matched 1  -> svc_sql

Every candidate carried a resolvable anchor id in a real index.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.config import Settings
from soc_ai.hunting.execute import MAX_SCOPE_BUCKETS, run_spec
from soc_ai.hunting.findings import candidate_findings
from soc_ai.hunting.spec import CATALOG_DIR, HuntSpec, load_catalog
from soc_ai.so_client.elastic import ElasticClient, EsSearchResult

pytestmark = pytest.mark.asyncio


def _spec(**over: Any) -> HuntSpec:
    base: dict[str, Any] = {
        "id": "t-spec",
        "title": "t",
        "scope_field": "host.name",
        "detection": {"all": [{"field": "event.code", "value": "4662"}]},
        "precondition": {"all": [{"field": "event.code", "value": "4662"}]},
    }
    return HuntSpec.model_validate({**base, **over})


def _result(total: int, buckets: list[dict[str, Any]] | None = None) -> EsSearchResult:
    aggs = {"scopes": {"buckets": buckets}} if buckets is not None else None
    return EsSearchResult(total=total, took_ms=1, hits=[], aggregations=aggs)


def _bucket(
    key: str, count: int, ids: list[str], index: str = ".ds-logs-x-000001"
) -> dict[str, Any]:
    return {
        "key": key,
        "doc_count": count,
        "first_seen": {"value_as_string": "2026-09-04T16:34:17.797Z"},
        "last_seen": {"value_as_string": "2026-09-04T16:35:51.192Z"},
        "samples": {"hits": {"hits": [{"_id": i, "_index": index} for i in ids]}},
    }


def _client(settings: Settings, results: list[Any]) -> ElasticClient:
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()):
        client = ElasticClient(settings)
    client.search = AsyncMock(side_effect=results)  # type: ignore[method-assign]
    return client


async def test_a_blind_spec_is_not_a_clean_one(settings_kratos: Settings) -> None:
    """Precondition empty: report blind, and do NOT run the detection.

    Running it would produce an empty result indistinguishable from a clean one,
    which is the entire failure this branch prevents.
    """
    client = _client(settings_kratos, [_result(0)])
    run = await run_spec(_spec(), elastic=client, settings=settings_kratos, since="a", until="b")
    assert run.blind is True
    assert run.clean is False
    assert run.candidates == []
    assert client.search.await_count == 1, "the detection must not run when blind"


async def test_a_clean_spec_saw_the_data_and_found_nothing(settings_kratos: Settings) -> None:
    client = _client(settings_kratos, [_result(4381), _result(0, buckets=[])])
    run = await run_spec(_spec(), elastic=client, settings=settings_kratos, since="a", until="b")
    assert run.blind is False
    assert run.clean is True
    assert run.precondition_docs == 4381


# ---------------------------------------------------------------------------
# The third query: documents no verdict could be reached on
# ---------------------------------------------------------------------------


def _excluding_spec(**over: Any) -> HuntSpec:
    """A spec whose precision comes from an exclusion, so it has a third query."""
    return _spec(
        detection={
            "all": [{"field": "event.code", "value": "4662"}],
            "none": [
                {"field": "winlog.event_data.SubjectUserName", "op": "wildcard", "value": "*$"}
            ],
        },
        **over,
    )


async def test_a_spec_with_no_exclusion_does_not_pay_for_a_third_query(
    settings_kratos: Settings,
) -> None:
    """Nothing can be undecided when no clause reads a field it might lack."""
    client = _client(settings_kratos, [_result(4381), _result(0, buckets=[])])
    run = await run_spec(_spec(), elastic=client, settings=settings_kratos, since="a", until="b")
    assert client.search.await_count == 2
    assert run.undecided_docs == 0
    assert run.clean is True


async def test_a_run_that_could_not_evaluate_its_exclusions_is_not_clean(
    settings_kratos: Settings,
) -> None:
    """The defect: a detection of zero over a precondition that says it could see.

    Measured on the development range over 2026-09-05, with the reconstructed
    4624 spec compiled by this module: precondition 10,844 and detection 5,240
    before the exclusion required its field present; 182 and 0 after. 182 is
    greater than zero, so the run was not blind, and it reported clean over
    5,240 documents that matched its positive clauses. Those documents are the
    third query, and while there is one of them the run is not clean.
    """
    client = _client(settings_kratos, [_result(5422), _result(5240), _result(0, buckets=[])])
    run = await run_spec(
        _excluding_spec(), elastic=client, settings=settings_kratos, since="a", until="b"
    )
    assert client.search.await_count == 3
    assert run.precondition_docs == 5422
    assert run.matched_docs == 0
    assert run.undecided_docs == 5240
    assert run.blind is False
    assert run.clean is False, "a run that discarded 5,240 documents reported an all-clear"


async def test_the_undecided_query_runs_before_the_detection(
    settings_kratos: Settings,
) -> None:
    """A failure counting them must stop the run, not land beside a bucket list.

    Ordered like the precondition and for the same reason: an unknown here means
    an unknown number of documents were dropped, and a candidate list published
    beside that unknown reads as the whole answer.
    """
    client = _client(settings_kratos, [_result(47), RuntimeError("mapping blew up")])
    run = await run_spec(
        _excluding_spec(), elastic=client, settings=settings_kratos, since="a", until="b"
    )
    assert client.search.await_count == 2, "the detection must not run"
    assert run.error is not None
    assert run.error.startswith("undecided: ")
    assert run.clean is False


async def test_an_undecided_run_reports_it_rather_than_nothing(
    settings_kratos: Settings,
) -> None:
    """The finding an analyst sees, and what it tells them to do about it."""
    client = _client(settings_kratos, [_result(5422), _result(5240), _result(0, buckets=[])])
    spec = _excluding_spec()
    run = await run_spec(spec, elastic=client, settings=settings_kratos, since="a", until="b")
    (finding,) = candidate_findings(spec, run)
    assert finding["category"] == "visibility_gap"
    assert "5240 document(s)" in finding["detail"]
    assert "winlog.event_data.SubjectUserName" in finding["detail"]
    assert "absent: match" in finding["detail"], "the reader needs the way out, not just the news"


def _two_exclusion_spec(**over: Any) -> HuntSpec:
    """Two exclusions on two fields, which is where the wording went wrong.

    The compiled undecided query asks for documents missing AT LEAST ONE of
    them, so a document that carries the first and lacks the second is in the
    count. Naming both fields as absent is then false about every document the
    sentence describes.
    """
    return _spec(
        detection={
            "all": [{"field": "event.code", "value": "4624"}],
            "none": [
                {"field": "winlog.event_data.SubjectUserName", "op": "wildcard", "value": "*$"},
                {"field": "user.name", "op": "wildcard", "value": "*$"},
            ],
        },
        **over,
    )


def _undecided_result(total: int, per_field: dict[str, int]) -> EsSearchResult:
    """The undecided query's answer, with the per-field breakdown it now asks for."""
    return EsSearchResult(
        total=total,
        took_ms=1,
        hits=[],
        aggregations={
            "missing_exclusion_field": {
                "buckets": {f: {"doc_count": n} for f, n in per_field.items()}
            }
        },
    )


async def test_the_undecided_query_asks_which_field_was_missing(
    settings_kratos: Settings,
) -> None:
    """One bucket per exclusion field, on the query that is already being run.

    Without it the finding can only name every exclusion field and assert all
    of them absent, which the query never required. Measured on a range with a
    reconstructed two-exclusion spec: 52 undecided documents, all 52 carrying
    the first field named and none carrying the second.
    """
    client = _client(
        settings_kratos,
        [
            _result(5422),
            _undecided_result(52, {"winlog.event_data.SubjectUserName": 52, "user.name": 0}),
            _result(0, buckets=[]),
        ],
    )
    run = await run_spec(
        _two_exclusion_spec(), elastic=client, settings=settings_kratos, since="a", until="b"
    )
    assert client.search.await_count == 3, "the breakdown rides the query already being run"
    aggs = client.search.await_args_list[1].kwargs["aggs"]
    assert set(aggs["missing_exclusion_field"]["filters"]["filters"]) == {
        "winlog.event_data.SubjectUserName",
        "user.name",
    }
    assert run.undecided_docs == 52
    assert dict(run.undecided_by_field) == {
        "winlog.event_data.SubjectUserName": 52,
        "user.name": 0,
    }


async def test_a_grid_without_the_breakdown_still_counts_the_undecided(
    settings_kratos: Settings,
) -> None:
    """The negative control for the aggregation: no buckets, no invented fields.

    An answer with no aggregation must not make the composer name a field on no
    evidence; it falls back to the wording the query does guarantee.
    """
    client = _client(settings_kratos, [_result(5422), _result(52), _result(0, buckets=[])])
    run = await run_spec(
        _two_exclusion_spec(), elastic=client, settings=settings_kratos, since="a", until="b"
    )
    assert run.undecided_docs == 52
    assert run.undecided_by_field == ()


async def test_candidates_carry_a_resolvable_anchor(settings_kratos: Settings) -> None:
    """`promote_finding` resolves a citation to a real ES id, so it cannot be synthesised."""
    client = _client(
        settings_kratos,
        [_result(47), _result(2, buckets=[_bucket("localuser", 2, ["idA", "idB"])])],
    )
    run = await run_spec(_spec(), elastic=client, settings=settings_kratos, since="a", until="b")
    (candidate,) = run.candidates
    assert candidate.scope_key == "localuser"
    assert candidate.doc_count == 2
    assert candidate.anchor_id == "idA"
    assert candidate.anchor_index == ".ds-logs-x-000001"
    assert candidate.sample_ids == ("idA", "idB")
    assert candidate.first_seen == "2026-09-04T16:34:17.797Z"


async def test_one_condition_is_one_candidate_not_one_per_document(
    settings_kratos: Settings,
) -> None:
    """The DCSync run wrote two documents for one act by one account."""
    client = _client(
        settings_kratos,
        [_result(47), _result(2, buckets=[_bucket("localuser", 2, ["idA", "idB"])])],
    )
    run = await run_spec(_spec(), elastic=client, settings=settings_kratos, since="a", until="b")
    assert len(run.candidates) == 1
    assert run.matched_docs == 2


async def test_every_bucket_becomes_a_candidate_truncation_is_the_gates_job(
    settings_kratos: Settings,
) -> None:
    """The query must not cap: doing so put the cut UPSTREAM of the fire-once gate.

    Once top_k noisy scopes were recorded terminal, a genuinely new scope ranked
    below them was cut by the aggregation, never reached the gate, never got a
    state row, and could never be surfaced. The budget belongs in one place.
    """
    buckets = [_bucket(f"h{i}", 1, [f"id{i}"]) for i in range(5)]
    client = _client(settings_kratos, [_result(9), _result(5, buckets=buckets)])
    run = await run_spec(
        _spec(top_k=3), elastic=client, settings=settings_kratos, since="a", until="b"
    )
    assert len(run.candidates) == 5, "run_spec must not apply top_k"


async def test_the_query_asks_for_a_fixed_ceiling_not_top_k(settings_kratos: Settings) -> None:
    client = _client(settings_kratos, [_result(9), _result(0, buckets=[])])
    await run_spec(_spec(top_k=3), elastic=client, settings=settings_kratos, since="a", until="b")
    aggs = client.search.await_args_list[1].kwargs["aggs"]
    assert aggs["scopes"]["terms"]["size"] == MAX_SCOPE_BUCKETS


async def test_a_candidate_names_the_hosts_its_own_documents_carry(
    settings_kratos: Settings,
) -> None:
    """A hit scoped on an account still names the machine that logged it.

    Without the related hosts the DCSync hit on the account and the off-hours
    departure on the domain controller sit in two leads, because nothing joins
    an account to a host. The samples carry the fields in either shape: a
    nested object, or the dotted key a flattened mapping writes.
    """
    hits = [
        {
            "_id": "a",
            "_index": ".ds-logs-x-000001",
            "_source": {"host": {"name": "dc01"}, "source": {"ip": "10.1.2.11"}},
        },
        {
            "_id": "b",
            "_index": ".ds-logs-x-000001",
            "_source": {"host.name": "dc01", "destination": {"ip": "224.0.0.251"}},
        },
    ]
    bucket = {
        "key": "localuser",
        "doc_count": 2,
        "first_seen": {"value_as_string": "2026-09-04T16:34:17.797Z"},
        "last_seen": {"value_as_string": "2026-09-04T16:35:51.192Z"},
        "samples": {"hits": {"hits": hits}},
    }
    spec = _spec(scope_field="winlog.event_data.SubjectUserName", scope_kind="user")
    client = _client(settings_kratos, [_result(47), _result(2, buckets=[bucket])])
    run = await run_spec(spec, elastic=client, settings=settings_kratos, since="a", until="b")
    source = client.search.await_args_list[1].kwargs["aggs"]["scopes"]["aggs"]["samples"][
        "top_hits"
    ]["_source"]
    assert "host.name" in source and "source.ip" in source
    # Sorted, deduplicated, and without the multicast address, which is the
    # host addressing the segment rather than a peer.
    assert run.candidates[0].hosts == ("10.1.2.11", "dc01")


async def test_a_candidate_does_not_name_itself_as_a_related_host(
    settings_kratos: Settings,
) -> None:
    # A host-scoped hit that named its own key would make every lead span an
    # entity it already holds.
    hits = [
        {
            "_id": "a",
            "_index": ".ds-logs-x-000001",
            "_source": {"host": {"name": "dc01"}, "destination": {"ip": "10.1.2.20"}},
        }
    ]
    bucket = {
        "key": "dc01",
        "doc_count": 1,
        "first_seen": {"value_as_string": "2026-09-04T16:34:17.797Z"},
        "last_seen": {"value_as_string": "2026-09-04T16:35:51.192Z"},
        "samples": {"hits": {"hits": hits}},
    }
    client = _client(settings_kratos, [_result(47), _result(1, buckets=[bucket])])
    run = await run_spec(_spec(), elastic=client, settings=settings_kratos, since="a", until="b")
    assert run.candidates[0].hosts == ("10.1.2.20",)


async def test_truncation_is_read_from_the_aggregation_not_guessed(
    settings_kratos: Settings,
) -> None:
    """``sum_other_doc_count`` is a fact; inferring from ``len(buckets)`` is a guess.

    The old form was ``max(0, len(buckets) - top_k)`` against a query that asked
    for ``top_k + 1`` buckets, so it could only ever be 0 or 1 — and 500 unseen
    scopes rendered as "1 further candidate held back".
    """
    aggs = {"scopes": {"buckets": [_bucket("a", 1, ["i"])], "sum_other_doc_count": 460}}
    client = _client(
        settings_kratos,
        [_result(9), EsSearchResult(total=500, took_ms=1, aggregations=aggs)],
    )
    run = await run_spec(_spec(), elastic=client, settings=settings_kratos, since="a", until="b")
    assert run.truncated_docs == 460
    assert run.clean is False


async def test_matched_documents_with_no_bucket_are_not_clean(
    settings_kratos: Settings,
) -> None:
    """Twelve matching documents that grouped nowhere used to report an all-clear.

    Reachable in the shipped catalog: two specs name their scope field only
    under ``none``, and an ES ``must_not`` does not exclude a document that
    lacks the field.
    """
    client = _client(settings_kratos, [_result(47), _result(12, buckets=[])])
    run = await run_spec(_spec(), elastic=client, settings=settings_kratos, since="a", until="b")
    assert run.candidates == []
    assert run.unattributed_docs == 12
    assert run.clean is False, "matched documents that grouped nowhere are not a clean result"


async def test_an_absence_judgement_refuses_a_partial_read(settings_kratos: Settings) -> None:
    """Both searches must ask for completeness, per ElasticClient.search's own contract.

    A degraded search returning nothing from the surviving shards is "could not
    see", never "clean", and this is the purest absence judgement in the
    codebase.
    """
    client = _client(settings_kratos, [_result(47), _result(0, buckets=[])])
    await run_spec(_spec(), elastic=client, settings=settings_kratos, since="a", until="b")
    for call in client.search.await_args_list:
        assert call.kwargs.get("require_complete") is True


async def test_a_grid_error_is_reported_rather_than_raised(settings_kratos: Settings) -> None:
    """A sweep must not lose every remaining spec because one hit a mapping error."""
    client = _client(settings_kratos, [_result(47), RuntimeError("field has no mapping")])
    run = await run_spec(_spec(), elastic=client, settings=settings_kratos, since="a", until="b")
    assert run.error is not None
    assert "mapping" in run.error
    assert run.clean is False, "an errored run is not a clean one"
    assert run.blind is False, "an errored run is not a blind one either"


async def test_a_precondition_error_does_not_masquerade_as_blind(
    settings_kratos: Settings,
) -> None:
    client = _client(settings_kratos, [RuntimeError("grid down")])
    run = await run_spec(_spec(), elastic=client, settings=settings_kratos, since="a", until="b")
    assert run.error is not None
    assert run.blind is False


async def test_a_spec_without_a_precondition_still_runs(settings_kratos: Settings) -> None:
    """The shipped catalog requires one; the executor does not force it."""
    spec = HuntSpec.model_validate(
        {
            "id": "no-pre",
            "title": "t",
            "detection": {"all": [{"field": "event.code", "value": "1"}]},
        }
    )
    client = _client(settings_kratos, [_result(1, buckets=[_bucket("h", 1, ["idA"])])])
    run = await run_spec(spec, elastic=client, settings=settings_kratos, since="a", until="b")
    assert client.search.await_count == 1
    assert len(run.candidates) == 1
    assert run.precondition_docs == 0


# ---------------------------------------------------------------------------
# A sensor with no heartbeat
# ---------------------------------------------------------------------------

# Ninety days, the look-back the shipped decoy spec carries.
LOOK_BACK_M = 90 * 24 * 60
SHIPPED_DECOY = load_catalog(CATALOG_DIR)["decoy-opencanary-interaction"]


def _no_heartbeat_spec() -> HuntSpec:
    """A spec whose sensor writes on an event rather than on a schedule."""
    return _spec(precondition_lookback_minutes=LOOK_BACK_M)


def _by_window(held: dict[str, int], detection: EsSearchResult) -> Any:
    """Answer a search from what the grid holds in the window the query asks for.

    The defect in one object. A honeypot's only document is its boot record from
    thirty days ago, so what the precondition counts depends on the window and
    on nothing else: asked over the sweep window the sensor looks absent, asked
    over its own look-back it looks alive. The detection is told apart by its
    aggregation, which the precondition query never carries.
    """

    async def search(index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        if kwargs.get("aggs"):
            return detection
        window = next(f for f in query["bool"]["filter"] if "range" in f)
        return _result(held.get(window["range"]["@timestamp"]["gte"], 0))

    return search


async def test_a_quiet_sensor_with_no_heartbeat_is_clean_not_a_coverage_gap(
    settings_kratos: Settings,
) -> None:
    """The inverse of the invariant the catalog is built on.

    Blind-is-never-clean stops an absence of visibility being reported as an
    all-clear. Without a look-back the decoy spec did the opposite: on any day
    nobody touched the honeypot it recorded a finding saying the telemetry was
    absent, when the silence was the good outcome and the marker was healthy.
    """
    client = _client(settings_kratos, [])
    client.search = AsyncMock(  # type: ignore[method-assign]
        side_effect=_by_window({f"now-61m-{LOOK_BACK_M}m": 8}, _result(0, buckets=[]))
    )
    run = await run_spec(
        _no_heartbeat_spec(), elastic=client, settings=settings_kratos, since="now-61m", until="now"
    )
    assert run.blind is False
    assert run.clean is True
    assert run.precondition_docs == 8


async def test_a_sensor_that_has_never_reported_still_reads_blind(
    settings_kratos: Settings,
) -> None:
    """The negative control. A look-back widens the question, it does not retire it.

    A honeypot nobody deployed, or one whose shipper died before the look-back
    began, holds no document in any window. That grid has no decoy telemetry and
    has to say so, which is the case a fix that merely stopped asking would
    break while every other test stayed green.
    """
    client = _client(settings_kratos, [])
    client.search = AsyncMock(  # type: ignore[method-assign]
        side_effect=_by_window({}, _result(0, buckets=[]))
    )
    run = await run_spec(
        _no_heartbeat_spec(), elastic=client, settings=settings_kratos, since="now-61m", until="now"
    )
    assert run.blind is True
    assert run.clean is False
    assert client.search.await_count == 1, "the detection must not run when blind"


async def test_the_detection_keeps_the_run_window_when_the_precondition_widens(
    settings_kratos: Settings,
) -> None:
    """A detection over ninety days would report ninety days of findings each sweep."""
    client = _client(settings_kratos, [])
    client.search = AsyncMock(  # type: ignore[method-assign]
        side_effect=_by_window({f"now-61m-{LOOK_BACK_M}m": 8}, _result(0, buckets=[]))
    )
    await run_spec(
        _no_heartbeat_spec(), elastic=client, settings=settings_kratos, since="now-61m", until="now"
    )
    windows = [
        next(f for f in call.args[1]["bool"]["filter"] if "range" in f)["range"]["@timestamp"]
        for call in client.search.await_args_list
    ]
    assert windows == [
        {"gte": f"now-61m-{LOOK_BACK_M}m", "lte": "now"},
        {"gte": "now-61m", "lte": "now"},
    ]


async def test_the_run_records_the_window_its_precondition_used(
    settings_kratos: Settings,
) -> None:
    """A blind report has to name the window it was blind over.

    "No telemetry in the last hour" is a false sentence about a spec that asked
    about ninety days, and the sentence is where the harm lands.
    """
    client = _client(settings_kratos, [])
    client.search = AsyncMock(  # type: ignore[method-assign]
        side_effect=_by_window({}, _result(0, buckets=[]))
    )
    blind = await run_spec(
        _no_heartbeat_spec(), elastic=client, settings=settings_kratos, since="now-61m", until="now"
    )
    assert blind.blind is True
    assert blind.precondition_since == f"now-61m-{LOOK_BACK_M}m"

    client.search = AsyncMock(  # type: ignore[method-assign]
        side_effect=_by_window({f"now-61m-{LOOK_BACK_M}m": 8}, _result(0, buckets=[]))
    )
    seeing = await run_spec(
        _no_heartbeat_spec(), elastic=client, settings=settings_kratos, since="now-61m", until="now"
    )
    assert seeing.precondition_since == f"now-61m-{LOOK_BACK_M}m"


async def test_a_spec_with_no_look_back_records_the_run_window(
    settings_kratos: Settings,
) -> None:
    """Every shipped identity spec is this case, and its reporting is unchanged."""
    client = _client(settings_kratos, [_result(47), _result(0, buckets=[])])
    run = await run_spec(_spec(), elastic=client, settings=settings_kratos, since="a", until="b")
    assert run.precondition_since == "a"


async def test_the_shipped_decoy_reads_clean_when_quiet_and_blind_when_absent(
    settings_kratos: Settings,
) -> None:
    """The catalog file, end to end, on the two grids that look identical to it.

    One grid has a healthy honeypot nobody touched today: its boot record is
    thirty days old, so the sweep window holds nothing and the look-back holds
    it. The other has no honeypot at all. Before the look-back both reported the
    same visibility gap, and the first of those reports was false.
    """
    quiet = _client(settings_kratos, [])
    quiet.search = AsyncMock(  # type: ignore[method-assign]
        side_effect=_by_window({f"now-61m-{LOOK_BACK_M}m": 8}, _result(0, buckets=[]))
    )
    healthy = await run_spec(
        SHIPPED_DECOY, elastic=quiet, settings=settings_kratos, since="now-61m", until="now"
    )
    assert healthy.blind is False
    assert healthy.clean is True

    silent = _client(settings_kratos, [])
    silent.search = AsyncMock(  # type: ignore[method-assign]
        side_effect=_by_window({}, _result(0, buckets=[]))
    )
    absent = await run_spec(
        SHIPPED_DECOY, elastic=silent, settings=settings_kratos, since="now-61m", until="now"
    )
    assert absent.blind is True
    (gap,) = candidate_findings(SHIPPED_DECOY, absent)
    assert "no documents at all in the 90 days to now" in gap["detail"]


def test_one_document_names_its_logging_host_once() -> None:
    # The domain controller appeared on a lead three times: as an address, an
    # FQDN and a short name. One document names the machine that logged it once.
    from soc_ai.hunting.execute import _related_hosts

    hits = [
        {
            "_id": "d1",
            "_source": {
                "host": {"ip": ["10.1.2.11"], "name": "SR-DC01.example.test"},
                "winlog": {"computer_name": "sr-dc01"},
                "source": {"ip": "10.1.2.21"},
            },
        }
    ]
    assert _related_hosts(hits, "localuser") == ("10.1.2.11", "10.1.2.21")
    # Without an address, the name stands in for the machine.
    hits[0]["_source"]["host"] = {"name": "SR-DC01.example.test"}
    assert _related_hosts(hits, "localuser") == ("10.1.2.21", "SR-DC01.example.test")
