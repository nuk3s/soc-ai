"""The read panels under a degraded Security Onion grid.

Batch E2 of the 2026-08-13 degraded-grid sweep. Three properties, all of which
the console got wrong, and none of which the existing outage tests covered.

**A sick grid is not a 500.** ``elasticsearch.ApiError`` is not an
``elastic_transport.TransportError`` — separate hierarchies — so a guard that
catches only the ``(TimeoutError, TransportError)`` tuple still lets every ES
4xx escape as an unhandled 500. Finding G11 survived the MR !70 fix for exactly
that reason: the test that shipped with the fix only ever killed the socket, and
a killed socket exercises the arm that was already there. The states where ES
*answers* with an error are the ones that find the missing arm, so every panel
here is crossed with both.

**A handled error still has to be the right error.** A saturated grid answers
429, which is a 4xx by number and a grid problem by nature. Sorted by number it
became "bad query — check the fields and time range", told to an analyst who on
two of these panels typed no query at all, and it hid the one useful fact: retry.
Hence the third grid state, and hence assertions on which answer, not just on
the absence of a traceback.

**A silent grid is not a hang.** A route that skips
``asyncio.timeout(webui_grid_timeout_s)`` sits on the ES client's full retry
budget — ``(1 + es_max_retries) x es_request_timeout_s``, about 90 s at shipped
defaults — against a grid that accepts the connection and never answers. The
screen hangs, each UI poll queues another request behind the last, and the
analyst concludes the app is broken. That is the sneakier half of G8: nothing
raises, nothing is logged, and the server looks perfectly healthy throughout.

The grid is stubbed at ``AsyncElasticsearch.search``, the transport seam, so the
real ``ElasticClient``, the real query modules and the real route all run: a
guard that only worked because the query layer was mocked out would not pass.

One panel deliberately answers differently — see ``_PANELS`` and
``test_egress_policy_reports_an_unknown_count_rather_than_a_zero``.

**A 200 is not always an answer.** A grid that reads only half its shards still
returns 200, carrying whatever the surviving shards held. That state was the
worst in this matrix — worse than every 500 above it, because a 500 is loud and
this one is quiet — and for a while these panels could not see it at all. Batch A
closed it in the client (``GridPartialResultsError``, subclassing
``elastic_transport.TransportError``), so it now arrives at the arms these panels
already had and is crossed here like any other transport failure.

The audit chain had two members of that class, both reading through the raw
``_client`` handle where batch A's guard never ran. The verifier pages with
``search_after`` (the wrapper has no such parameter) and reported an intact
chain from a half-read index; it now carries its own per-page check in
``soc_ai/audit/verify.py`` — see
``test_a_half_read_audit_index_is_unverifiable_never_an_intact_chain``. The
logger's chain-head recovery read the same index the same way at WRITE time,
where a half-read was quieter and costlier: a stale top hit resumed the chain
from an old seq and an empty page restarted it at genesis, either of which
turns every later verify into a permanent false TAMPER. It shares the same
guard now — pinned in ``tests/test_audit.py``.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, patch

import anyio
import pytest
from elastic_transport import ApiResponseMeta, HttpHeaders
from elastic_transport import ConnectionError as EsConnectionError
from elasticsearch import ApiError, BadRequestError
from fastapi import Request
from fastapi.testclient import TestClient
from soc_ai.api.webui.routes_config import _recent_fitness_checks
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.so_client.elastic import ElasticClient

# RFC 5737 documentation address — never a real host on anyone's network.
_HOST_IP = "192.0.2.10"


def _client(settings: Settings, *, es_search: Any) -> Iterator[TestClient]:
    """The app on a scratch DB with the grid stubbed at the transport seam.

    ``raise_server_exceptions=False`` on purpose. The default re-raises an
    unhandled handler exception into the test, which fails the test but never
    runs the ``status_code != 500`` assertion — so the assertion this whole batch
    turns on would be decorative. Off, the client sees what the analyst's browser
    sees: Starlette's plain-text 500.
    """
    fake_es = AsyncMock()
    fake_es.search.side_effect = es_search
    # ``info`` answers like a live cluster. Left as a bare AsyncMock it returns a
    # coroutine from ``.get()``, so ``ElasticClient.ping`` raises an AttributeError
    # and every probe that pings first short-circuits before it ever reaches the
    # read — which would make a "the read is bounded" assertion pass without a
    # bound existing. It also models the state under test more honestly: in
    # ``stalled`` the grid accepted connections and answered cluster info; what it
    # never finished was a search.
    fake_es.info.return_value = {
        "cluster_name": "documentation-cluster",
        "version": {"number": "8.0.0"},
    }
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app, raise_server_exceptions=False) as client:
            yield client


@dataclass(frozen=True)
class _Panel:
    """One read panel and what it owes each degraded-grid state."""

    id: str
    path: str
    # What the panel answers when the transport fails (refused, timed out, or
    # cut short by the console's own grid budget), and when Elasticsearch answers
    # 400. See the egress entry below for the one panel that owes neither.
    transport_status: int
    api_error_status: int
    # What a healthy but empty grid answers, so no fix can be "always degrade".
    healthy_status: int = 200
    params: dict[str, str] = field(default_factory=dict)


_PANELS = [
    _Panel("detection-tuning", "/api/v1/detection-tuning", 503, 400),
    _Panel("dossier-activity", f"/api/v1/dossiers/{_HOST_IP}/activity", 503, 400),
    _Panel(
        "alerts-representative",
        "/api/v1/alerts/representative",
        503,
        400,
        # An empty window genuinely has no representative event to pick, and 404
        # is this route's documented answer for that.
        healthy_status=404,
        params={"rule_name": "ET DOCUMENTATION TEST RULE"},
    ),
    # The egress-policy page's load-bearing answer — which destinations are
    # enabled, and therefore whether this deployment egresses at all — comes from
    # Settings and stays knowable while the grid is down. Only the 7-day audit
    # counter needs the grid, and it degrades to an honest null. Answering 503
    # would make "prove you are not shipping my data off-box" unanswerable during
    # an outage, so this panel owes 200. It still owes it INSIDE the grid budget,
    # and it still owes "unknown" rather than "zero".
    _Panel("egress-policy", "/api/v1/config/egress-policy", 200, 200),
]

_PANEL_IDS = [p.id for p in _PANELS]


def _es_ok(**_kwargs: Any) -> dict[str, Any]:
    """A healthy, empty ES search response."""
    return {
        "took": 2,
        "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
        "aggregations": {},
    }


def _raise_connection_error(**_kwargs: Any) -> dict[str, Any]:
    raise EsConnectionError("connection refused")


def _raise_api_error(**_kwargs: Any) -> dict[str, Any]:
    """Elasticsearch answering 400 — an ApiError, NOT a TransportError."""
    meta = ApiResponseMeta(400, "HTTP/1.1", HttpHeaders(), 0.0, None)
    raise BadRequestError("search_phase_execution_exception", meta=meta, body={})


def _raise_saturated(**_kwargs: Any) -> dict[str, Any]:
    """Elasticsearch answering 429 — search queue full / circuit breaker tripped.

    A 4xx by number and a grid problem by nature: nothing is wrong with the query,
    the cluster is over its limits and the same request works once it recovers.
    elasticsearch-py has no dedicated class for it (``HTTP_EXCEPTIONS`` maps
    400/401/403/404/409 only), so a saturated grid arrives as a bare ``ApiError``.
    """
    meta = ApiResponseMeta(429, "HTTP/1.1", HttpHeaders(), 0.0, None)
    raise ApiError(
        "circuit_breaking_exception",
        meta=meta,
        body={"error": {"type": "circuit_breaking_exception"}},
    )


def _shards_failed(**_kwargs: Any) -> dict[str, Any]:
    """A 200 that is not an answer: half the shards never reported.

    Elasticsearch defaults ``allow_partial_search_results=true``, so a search over
    a cluster with red shards returns 200 carrying whatever the surviving shards
    happened to hold, and says so only in ``timed_out`` and ``_shards``. Nothing
    raises. A node dying or shards going red during a restart is the ordinary
    failure mode of a real grid, not an exotic one.

    This was the worst state in the matrix and for a while the panels could not
    see it at all: the client read ``hits``/``total``/``took``/``aggregations``
    and dropped ``_shards`` and ``timed_out``, so by the time a route saw the
    result the evidence that the read was partial no longer existed. Every panel
    then drew a calm network from a blind sensor — an empty peer list ("this host
    talked to nobody"), no noisy rules, no events to hunt. Batch A's
    ``GridPartialResultsError`` closed it in one raise in the client, subclassing
    ``elastic_transport.TransportError`` so the arms these panels already had
    caught it with no further edits. Hence ``transport_status`` below: a half-read
    grid is now just another way the transport failed.
    """
    return {
        "took": 9,
        "timed_out": True,
        "_shards": {
            "total": 4,
            "successful": 2,
            "skipped": 0,
            "failed": 2,
            "failures": [
                {
                    "shard": 0,
                    "index": "logs-example-000001",
                    "reason": {"type": "no_shard_available_action_exception"},
                }
            ],
        },
        "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
        "aggregations": {},
    }


@dataclass(frozen=True)
class _GridState:
    """One way the grid fails, and which of the panel's two answers it owes."""

    id: str
    search: Any
    # Name of the _Panel field carrying the status this state owes. A state is
    # not "a 4xx" or "a transport error" — it is a story ("your query is wrong"
    # vs "the grid is sick"), and 429 tells the second story with a 4xx number.
    owes: str


_STATES = [
    _GridState("connection-refused", _raise_connection_error, "transport_status"),
    _GridState("es-answers-400", _raise_api_error, "api_error_status"),
    _GridState("es-answers-429", _raise_saturated, "transport_status"),
    _GridState("shards-failed", _shards_failed, "transport_status"),
]


def _assert_panel_answered(panel: _Panel, resp: Any, expected: int, *, state: str) -> None:
    """The full contract for one panel in one grid state.

    ``!= 500`` is called out separately from the equality because it is the
    assertion that catches this whole class at once: a 500 is an ASGI traceback
    in the log and a "Couldn't load this view / Internal Server Error" card in
    the console, which tells the analyst nothing about whether to retry.
    """
    assert resp.status_code != 500, f"{panel.id} leaked an unhandled 500 on a {state} grid"
    assert resp.status_code == expected, f"{panel.id} on a {state} grid"
    if expected == 503:
        # 503 alone is not enough: the SPA keys its retryable grid card on the
        # reason, and an unnamed 503 renders as a generic failure.
        assert resp.json()["detail"]["reason"] == "grid_unavailable"


# ---------------------------------------------------------------------------
# 1. A failing grid is answered, not crashed into
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("panel", _PANELS, ids=_PANEL_IDS)
@pytest.mark.parametrize("state", _STATES, ids=[s.id for s in _STATES])
def test_a_failing_grid_is_never_an_unhandled_500(
    settings_kratos: Settings, panel: _Panel, state: _GridState
) -> None:
    """Each panel answers each failure with the story that failure actually tells.

    The 429 row is the one that separates "is this handled" from "is this true".
    A blanket 4xx→400 mapping handles it — no 500, no traceback — and tells the
    analyst to check fields and a time range they never typed, on a panel whose
    range is a fixed toggle, while the real answer is "the grid is over its
    limits, retry". Handled and wrong is still wrong.
    """
    expected = getattr(panel, state.owes)
    assert isinstance(expected, int)
    for client in _client(settings_kratos, es_search=state.search):
        _assert_panel_answered(
            panel, client.get(panel.path, params=panel.params), expected, state=state.id
        )


def test_egress_policy_reports_an_unknown_count_rather_than_a_zero(
    settings_kratos: Settings,
) -> None:
    """The one panel that stays 200 must not price an outage as "never fired".

    A null renders as an em dash; a 0 would be a positive statement that no
    Oracle escalation and no notification left this deployment in seven days —
    the false all-clear this whole sweep exists to stop. Asserting on the status
    code alone would miss it entirely.
    """
    for client in _client(settings_kratos, es_search=_raise_api_error):
        body = client.get("/api/v1/config/egress-policy").json()
        counted = {d["id"]: d["count_7d"] for d in body["destinations"]}
        # The two destinations with a mapped audit kind — the only ones that can
        # ever carry a real number, and so the only ones that could lie.
        assert counted["oracle"] is None
        assert counted["notifications"] is None
        # The settings-derived half of the page still answers, which is why this
        # panel is allowed to stay 200 at all.
        assert body["zero_egress"] is True


# ---------------------------------------------------------------------------
# 1b. The half-read audit index — unverifiable, never a verdict either way
# ---------------------------------------------------------------------------


def test_a_half_read_audit_index_is_unverifiable_never_an_intact_chain(
    settings_kratos: Settings,
) -> None:
    """The endpoint that exists to prove nothing was tampered with does not guess.

    ``GET /config/audit/verify-chain`` recomputes the audit hash chain, and its
    own docstring is emphatic that it is NOT fail-soft: a verification it could
    not run is "could not run", never "intact". It held that line against every
    failure that raises — a refused grid is a 502 elsewhere in this file — but
    not against the one that does not: ``_search_page`` pages through the raw
    ``_client`` handle (the wrapper has no ``search_after``), so batch A's
    partial-read guard never ran, an index whose shards were half down paged to
    zero records, and "an empty chain is intact by definition" did the rest.
    ``ok: true`` off records that were never read, on the one screen whose
    entire purpose is to be believed about integrity.

    The fix lives in ``soc_ai/audit/verify.py`` (shared with the ``soc-ai audit
    verify`` CLI, which maps the same raise to exit 2), and the answer must be
    the honest middle: not an intact chain, not a tamper verdict — "could not
    read the whole index, so the chain cannot be verified", with the shard story
    attached so an operator can tell this 502 from a refused connection.
    """
    for client in _client(settings_kratos, es_search=_shards_failed):
        resp = client.get("/api/v1/config/audit/verify-chain")

    assert resp.status_code == 502, (
        f"a half-read audit index answered {resp.status_code}: a verification that "
        "read half its shards is 'could not run', never a verdict"
    )
    detail = resp.json()["detail"]
    assert detail["reason"] == "audit_verify_failed"
    # The shard story, so "unverifiable" is distinguishable from every other 502.
    message = detail["message"]
    assert "shards failed" in message, f"no shard story in the refusal: {message!r}"
    assert "cannot be verified" in message, f"the refusal does not say why: {message!r}"
    # And NOT a tamper claim: an outage must never land in the same bucket as a
    # genuine hash mismatch (which is a 200 with ok=false + first_broken_seq).
    assert "first_broken_seq" not in detail
    assert "tamper" not in message.lower()

    # The over-correction control: a healthy grid still verifies. _es_ok carries
    # no _shards block at all — absent metadata must read as zero failures, or
    # every stubbed and replayed response in the product becomes "unverifiable".
    for client in _client(settings_kratos, es_search=_es_ok):
        resp = client.get("/api/v1/config/audit/verify-chain")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["records_verified"] == 0


# ---------------------------------------------------------------------------
# 2. A silent grid is answered inside the console's budget, not the transport's
# ---------------------------------------------------------------------------


@pytest.fixture
def stalled_settings(settings_kratos: Settings) -> Settings:
    """Grid budget squeezed to a second so this costs seconds, not minutes.

    ``webui_grid_timeout_s`` is an int, so 1 is the floor. Every assertion below
    reads the budget back off this object rather than hardcoding a number, so
    changing the shipped default cannot silently decouple the test from it.
    """
    return settings_kratos.model_copy(update={"webui_grid_timeout_s": 1})


@pytest.mark.parametrize("panel", _PANELS, ids=_PANEL_IDS)
def test_a_grid_that_accepts_and_never_answers_does_not_hang_the_panel(
    stalled_settings: Settings, panel: _Panel
) -> None:
    """The tarpit case: ES holds the connection open and eventually replies fine.

    Nothing raises, so none of the guards in part 1 fire. Without
    ``asyncio.timeout(webui_grid_timeout_s)`` the route waits out the ES client's
    whole retry budget — ~90 s at shipped defaults — and the console reads as
    frozen while the server is healthy. Timing out must also produce the degraded
    signal rather than a plausible empty view: an empty peers list or an empty
    nomination list would say "this host did nothing" / "no rule is noisy" about
    a window nothing could be read in.
    """
    budget = stalled_settings.webui_grid_timeout_s
    # Stands in for the transport's retry budget: long enough that answering
    # inside the console budget can only mean the wrapper fired.
    stall_s = budget * 6

    async def _tarpit(**_kwargs: Any) -> dict[str, Any]:
        await anyio.sleep(stall_s)
        return _es_ok()

    for client in _client(stalled_settings, es_search=_tarpit):
        started = time.perf_counter()
        resp = client.get(panel.path, params=panel.params)
        elapsed = time.perf_counter() - started
        assert elapsed < budget * 2, (
            f"{panel.id} took {elapsed:.1f}s against a silent grid — it is waiting on the "
            f"ES retry budget, not on webui_grid_timeout_s={budget}"
        )
        _assert_panel_answered(panel, resp, panel.transport_status, state="silent")


def test_the_audit_chain_verifier_takes_as_long_as_it_takes_but_never_lies(
    stalled_settings: Settings,
) -> None:
    """The one grid read in these files that is deliberately NOT capped at the budget.

    Every other route here is a console poll: the analyst is watching, the SPA
    re-polls, and a bounded 503 beats a spinner. Verify-chain is not a poll. It is
    an admin pressing a button to page the entire audit trail — up to 500 000
    records at 1 000 per request, so up to 500 sequential round trips — and it is
    the one endpoint that must never trade truth for speed.

    Capping it at ``webui_grid_timeout_s`` would do exactly that. The local half of
    the work is nearly free (measured: 100 000 records over 100 pages against an
    instant grid costs 0.76 s of paging and hashing), so the wall clock is round
    trips almost entirely, and 500 of them do not fit in 12 s at any real ES
    latency. The cap would fire on a working grid that was merely busy, and the
    honest-by-design 502 would then report "could not run" for a chain that was
    fine — a tamper-evidence check turned into a false alarm to save an admin some
    seconds. A per-page bound is the right shape and it belongs in
    ``soc_ai/audit/verify.py`` beside the paging loop, where the ``soc-ai audit
    verify`` CLI picks it up too; it is not this route's to add.

    So: slow is allowed here, dishonest is not. This pins both halves.
    """
    budget = stalled_settings.webui_grid_timeout_s
    stall_s = budget * 3

    async def _tarpit(**_kwargs: Any) -> dict[str, Any]:
        await anyio.sleep(stall_s)
        return _es_ok()

    for client in _client(stalled_settings, es_search=_tarpit):
        started = time.perf_counter()
        resp = client.get("/api/v1/config/audit/verify-chain")
        elapsed = time.perf_counter() - started
        assert elapsed > budget, (
            f"verify-chain answered in {elapsed:.1f}s, inside webui_grid_timeout_s={budget}. "
            "If that is a per-page bound, good — relax this assertion. If the whole scan "
            "was capped at the console budget, revert it: a long chain on a busy grid will "
            "trip the cap and report a fine chain as 'could not run'."
        )
        assert resp.status_code == 200  # a slow grid that DOES answer is still an answer

    for client in _client(stalled_settings, es_search=_raise_connection_error):
        resp = client.get("/api/v1/config/audit/verify-chain")
        assert resp.status_code == 502, "a chain that could not be read is not an intact chain"
        assert resp.json()["detail"]["reason"] == "audit_verify_failed"


class _StallsAfterLanding:
    """The stalled grid's index call: the record LANDS, the answer never comes.

    That is the ordinary shape of a stall. A cluster too busy to answer is still
    a cluster that accepted the write — ``stalled`` was built by making searches
    slow, not by refusing them — so "the bound expired" and "the record did not
    land" are different statements, and only one of them is knowable from here.

    ``search`` serves the landed records back the way ES would, so a logger that
    re-reads the chain head finds the truth rather than a stub's fiction.
    """

    def __init__(self) -> None:
        self.docs: list[dict[str, Any]] = []
        self.stall = False
        self.indices = AsyncMock()  # put_index_template is a no-op here

    async def index(self, *, index: str, body: dict[str, Any]) -> None:
        self.docs.append(body)  # it landed...
        if self.stall:
            await anyio.sleep_forever()  # ...and the acknowledgement never arrives

    async def search(self, *, index: str, body: dict[str, Any]) -> dict[str, Any]:
        chained = [d for d in self.docs if d.get("seq") is not None]
        if not chained:
            return {"hits": {"hits": []}}
        return {"hits": {"hits": [{"_source": max(chained, key=lambda d: d["seq"])}]}}


async def test_a_write_that_outran_its_bound_does_not_leave_a_duplicate_seq(
    stalled_settings: Settings,
) -> None:
    """One stalled episode must not become a permanent false tamper verdict.

    The audit write is bounded now, and a bound turns a hang into an outcome the
    logger cannot classify: the index request is on the wire when it expires, so
    the record may well be in the index while the in-memory head still points at
    its predecessor. The next write then reuses that ``seq``, and ``verify_chain``
    is unambiguous about what a repeated seq means — "a record was inserted,
    deleted, reordered, or edited" — so the trail reads TAMPERED at that seq,
    forever, for a grid that was merely slow. On the one surface whose entire job
    is to be believed about integrity, that is the most expensive false alarm the
    product can raise.

    The fix is not to guess. An expired write leaves the head UNKNOWN, and the
    next write re-reads it from the index — which is correct whichever way the
    ambiguous record went, and costs one search inside that write's own bound.
    """
    from soc_ai.audit.chain import verify_chain
    from soc_ai.audit.logger import AuditLogger
    from soc_ai.audit.schemas import AuditEvent

    es = _StallsAfterLanding()
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=es):
        logger = AuditLogger(stalled_settings, ElasticClient(stalled_settings))

    def _event(note: str) -> AuditEvent:
        return AuditEvent(session_id="sid-1", kind="tool_call", payload={"note": note})

    # A healthy write first: the head has to be established for the reuse to be
    # possible at all — from genesis the next write re-reads anyway.
    await logger.log(_event("before the stall"))
    es.stall = True
    await logger.log(_event("during the stall"))  # lands; the bound expires
    es.stall = False
    await logger.log(_event("after the stall"))

    seqs = [d["seq"] for d in es.docs]
    assert len(es.docs) == 3, f"the test did not exercise three writes: {seqs}"
    assert len(set(seqs)) == 3, (
        f"a stalled write left the chain head behind and the next record reused its seq: "
        f"{seqs} — verify-chain calls that an inserted or edited record"
    )
    ok, first_broken = verify_chain(es.docs)
    assert ok, (
        f"a slow grid broke the audit chain at seq {first_broken}: the operator is now told "
        f"their audit trail was tampered with, permanently, by an outage. Records: {seqs}"
    )


async def test_a_head_re_read_that_cannot_reach_the_grid_does_not_restart_at_genesis(
    stalled_settings: Settings,
) -> None:
    """The control on the recovery above, and on the obvious way to write it.

    Marking the head unknown as ``_seq = -1`` + genesis prev-hash — the shape
    ``_ensure_chain_head`` already uses for "not initialised" — recovers
    correctly only when the re-read succeeds. It usually will not: the grid that
    just stalled a write is the grid the re-read has to go through. That path
    falls back to genesis, and genesis on a chain that already has records
    renumbers every future record from 0, duplicating every seq in the index and
    linking the next record to a predecessor that is not there. One recoverable
    seq becomes a trail broken from its first record.

    So a re-read that comes back empty-handed keeps the last known head instead.
    That is exactly what the logger did before any of this existed — the failed
    write may still duplicate its seq — and no worse. This test is green before
    and after the fix; it goes red against the naive invalidation.
    """
    from soc_ai.audit.chain import GENESIS_PREV_HASH
    from soc_ai.audit.logger import AuditLogger
    from soc_ai.audit.schemas import AuditEvent

    es = _StallsAfterLanding()
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=es):
        logger = AuditLogger(stalled_settings, ElasticClient(stalled_settings))

    def _event(note: str) -> AuditEvent:
        return AuditEvent(session_id="sid-1", kind="tool_call", payload={"note": note})

    await logger.log(_event("before the stall"))
    es.stall = True
    await logger.log(_event("during the stall"))  # lands; the bound expires
    es.stall = False

    async def _refuses(**_kwargs: Any) -> dict[str, Any]:
        raise EsConnectionError("connection refused")

    es.search = _refuses  # type: ignore[method-assign]
    await logger.log(_event("after the stall, head unreadable"))

    seqs = [d["seq"] for d in es.docs]
    assert seqs[-1] != 0, (
        f"an unreadable chain head restarted the chain at genesis: {seqs}. Every later "
        "record is now renumbered from 0 over records that already exist — a far bigger "
        "break than the one seq this recovery exists to avoid"
    )
    assert es.docs[-1]["prev_hash"] != GENESIS_PREV_HASH, (
        "the record after an unreadable head claims to be the first in the chain"
    )


async def test_a_grid_that_answers_writes_is_not_re_read_on_every_event(
    settings_kratos: Settings,
) -> None:
    """The over-correction control on the recovery above.

    Re-reading the chain head is a full ES search. Doing it per write — rather
    than only after an outcome nobody can classify — puts an extra round trip in
    front of every tool call in every investigation, on a healthy grid, to guard
    against something that did not happen. The head is in memory precisely so the
    steady state costs nothing.
    """
    from soc_ai.audit.logger import AuditLogger
    from soc_ai.audit.schemas import AuditEvent

    es = _StallsAfterLanding()
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=es):
        logger = AuditLogger(settings_kratos, ElasticClient(settings_kratos))

    searches = 0
    real_search = es.search

    async def _counting_search(**kwargs: Any) -> dict[str, Any]:
        nonlocal searches
        searches += 1
        return await real_search(**kwargs)

    es.search = _counting_search  # type: ignore[method-assign]
    for n in range(4):
        await logger.log(AuditEvent(session_id="sid-1", kind="tool_call", payload={"n": n}))

    assert [d["seq"] for d in es.docs] == [0, 1, 2, 3]
    assert searches <= 1, (
        f"a healthy grid paid {searches} chain-head searches for 4 audit writes — the "
        "in-memory head is there so the steady state costs one round trip, not two"
    )


class _StubRequest:
    """Just enough ``Request`` for a handler that only reads ``app.state``."""

    def __init__(self, state: Any) -> None:
        self.app = SimpleNamespace(state=state)


async def test_the_fitness_chip_forgets_its_history_rather_than_freezing_the_page(
    stalled_settings: Settings,
) -> None:
    """The model-fitness history read, which no panel route in ``_PANELS`` covers.

    It is reached from ``GET /config/model-fitness``, whose other half probes the
    LLM gateway, so it can't join the panel matrix without dragging a model stub
    behind it — and left untested it was the one bound in this batch that a
    refactor could delete with the suite staying green.

    Two properties, and the second is the one that matters. Inside the budget:
    the Config page must not freeze on a chip. And ``None``, never ``[]``: the
    caller reads an empty list as a history it successfully read and found empty,
    and then grades a fresh FAIL as "1 of 1 checks" — a clean record asserted off
    a query that never returned.
    """
    budget = stalled_settings.webui_grid_timeout_s
    stall_s = budget * 6

    async def _tarpit(**_kwargs: Any) -> dict[str, Any]:
        await anyio.sleep(stall_s)
        return _es_ok()

    fake_es = AsyncMock()
    fake_es.search.side_effect = _tarpit
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        elastic = ElasticClient(stalled_settings)

    request = cast("Request", _StubRequest(SimpleNamespace(elastic=elastic)))
    started = time.perf_counter()
    history = await _recent_fitness_checks(
        request, stalled_settings, model="documentation-model", limit=5
    )
    elapsed = time.perf_counter() - started

    assert elapsed < budget * 2, (
        f"the fitness history read took {elapsed:.1f}s against a silent grid — it is "
        f"waiting on the ES retry budget, not on webui_grid_timeout_s={budget}"
    )
    assert history is None, "an unreadable history must be unknown, not empty"


# ---------------------------------------------------------------------------
# 2b. The four ACTIONS with no server-side budget at all (D12, dogfood 2026-08-14)
#
# The panels above are polls. These four are things an analyst CLICKS, and none
# of them had a wrapper: against a grid that accepts the connection and never
# answers, `stalled/network.json` recorded every one of them aborted by the
# BROWSER at 19,999-20,000 ms (REQUEST_TIMEOUT_MS in frontend/src/lib/api.ts).
# The words on screen were honest — "Request timed out" — but the diagnosis came
# from the client giving up, and a client that abandoned a request cannot know
# whether the work it asked for started. That is what makes the bulk-investigate
# toast unable to say so.
#
# Two of the four are worth naming individually. Test-ES is the control whose
# entire job is diagnosing the grid, so answering "your request timed out" is it
# declining to do the one thing it exists for. And model-fitness was an audit
# WRITE with no bound of its own, stacked behind a 12 s history read: two legs,
# one budget between them, and the sum landed past the browser's patience.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Action:
    """One clickable action and what it owes against a grid that never answers."""

    id: str
    method: str
    path: str
    body: dict[str, Any] | None
    silent_status: int
    # Console budgets this action may spend before it has to answer. Three is
    # "one bounded grid read, plus generous slack for a loaded CI box" — the
    # failure it rules out is 10-40 s of ES retry budget, so the threshold has
    # a factor of ten in hand and buys flake resistance for free. The multiplier
    # is on the SETTING, never on a number, so raising the shipped default can't
    # silently decouple the assertion from the bound it checks.
    budgets: int = 3
    # Share of the budget ONE read may take in the slow-but-working control.
    # It is not simply "just under 1" for two actions, and both reasons are real
    # properties of the code rather than test tuning:
    #   - auto-triage plans with a fan-out (groups per severity, two searches
    #     each with webui_extra_detections on) under a SINGLE wrapper, so what
    #     the budget promises is "planning that FITS in it succeeds", not "any
    #     per-read latency below it succeeds". The other side of that is pinned
    #     in test_planning_that_outruns_its_shared_budget_still_does_not_cry_outage.
    #   - model-fitness passes through a TIGHTER bound than the console read:
    #     its audit write gets the best-effort slice, a quarter of the budget.
    slow_read_share: float = 0.4


_ACTIONS = [
    # probe_es never raises, so nothing here was ever going to be caught by an
    # except arm — it simply did not come back.
    _Action("test-es", "POST", "/api/v1/config/danger/test/es", None, 200),
    _Action(
        "auto-triage", "POST", "/api/v1/auto-triage", {"range": "24h"}, 503, slow_read_share=0.1
    ),
    _Action("backtest", "POST", "/api/v1/backtest", {"window_days": 30}, 503),
    # Four, not three: this route reads its n-of-m history under one budget and
    # then writes an audit record under the best-effort slice, which floors at
    # 1 s — so at webui_grid_timeout_s=1 the two bounded legs already sum to two
    # budgets before any slack. Still an order of magnitude inside the ES client's
    # retry budget, which is the thing being ruled out.
    _Action(
        "model-fitness",
        "GET",
        "/api/v1/config/model-fitness",
        None,
        200,
        budgets=4,
        slow_read_share=0.1,
    ),
]

_FAKE_FITNESS = {
    "grade": "pass",
    "model": "documentation-model",
    "legs": [],
    "detail": "probe stubbed — this test is about the grid legs, not the gateway",
}


async def _fake_probe_model_fitness(_settings: Any) -> dict[str, Any]:
    """Stand in for the gateway probe so the route's two GRID legs are what's timed."""
    return dict(_FAKE_FITNESS)


@pytest.mark.parametrize("action", _ACTIONS, ids=[a.id for a in _ACTIONS])
def test_a_grid_that_never_answers_is_the_servers_verdict_not_the_browsers(
    stalled_settings: Settings, action: _Action
) -> None:
    """Each action answers inside its own budget instead of outliving the client.

    The elapsed assertion is the whole finding. Without a wrapper these sit on
    the ES client's retry budget — ``(1 + es_max_retries) x es_request_timeout_s``,
    ~90 s at shipped defaults — and the only thing that ends the wait is the
    browser's 20 s abort, which produces a verdict the server never made.
    """
    budget = stalled_settings.webui_grid_timeout_s
    # Stands in for the transport's retry budget: long enough that answering
    # inside the console budget can only mean a wrapper fired.
    stall_s = budget * 10

    async def _tarpit(**_kwargs: Any) -> dict[str, Any]:
        await anyio.sleep(stall_s)
        return _es_ok()

    with patch("soc_ai.webui.probes.probe_model_fitness", _fake_probe_model_fitness):
        for client in _client(stalled_settings, es_search=_tarpit):
            started = time.perf_counter()
            resp = client.request(action.method, action.path, json=action.body)
            elapsed = time.perf_counter() - started

    assert elapsed < budget * action.budgets, (
        f"{action.id} took {elapsed:.1f}s against a silent grid — it is waiting on the ES "
        f"retry budget, not on webui_grid_timeout_s={budget}, so the browser gets to the "
        "verdict first"
    )
    assert resp.status_code == action.silent_status, f"{action.id} on a silent grid"


def test_the_es_connection_test_states_a_verdict_when_the_grid_goes_quiet(
    stalled_settings: Settings,
) -> None:
    """Diagnostics' one grid control must produce a DIAGNOSIS, not a client error.

    Answering inside the budget is not enough on this one. It is the control an
    admin presses to find out whether Security Onion is up; "the request timed
    out" hands that question back to them unanswered, and it is what the screen
    said because the browser, not the server, ended the wait. A grid that accepts
    a connection and then answers nothing is down as far as this console is
    concerned, and the response has to say so — with the budget it waited, so the
    admin can tell a verdict from a guess.
    """
    budget = stalled_settings.webui_grid_timeout_s

    async def _tarpit(**_kwargs: Any) -> dict[str, Any]:
        await anyio.sleep(budget * 10)
        return _es_ok()

    for client in _client(stalled_settings, es_search=_tarpit):
        body = client.post("/api/v1/config/danger/test/es").json()

    assert body["ok"] is False, "a grid that answers nothing is not a passing connection test"
    detail = str(body["detail"])
    assert "down" in detail.lower(), f"no verdict in the Test ES detail: {detail!r}"
    assert f"{budget}s" in detail, (
        f"the Test ES verdict does not say how long it waited: {detail!r} — an admin cannot "
        "tell a bounded verdict from a guess without it"
    )


def test_auto_triage_that_ran_out_of_budget_does_not_publish_a_swept_backlog(
    stalled_settings: Settings,
) -> None:
    """The planner is the sole writer of the degraded marks; a cancelled one wrote nothing.

    Landing this as a finished run would take ``grid_errors`` from whatever the
    LAST run left there and publish it as this one's — and on a fresh process
    that is an empty list, i.e. ``degraded: false`` beside ``total: 0``, which
    the dashboard tile renders as a swept, clean backlog. A sweep that never
    started must not be reported as a sweep that found nothing.
    """
    budget = stalled_settings.webui_grid_timeout_s

    async def _tarpit(**_kwargs: Any) -> dict[str, Any]:
        await anyio.sleep(budget * 10)
        return _es_ok()

    for client in _client(stalled_settings, es_search=_tarpit):
        resp = client.post("/api/v1/auto-triage", json={"range": "24h"})
        after = client.get("/api/v1/auto-triage").json()

    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "grid_unavailable"
    # The single-flight slot is released, or every later sweep no-ops with
    # "already running" until the process restarts.
    assert after["active"] is False
    # ...and nothing was written down as a completed sweep of an empty backlog.
    assert after["finished_at"] is None, (
        "a sweep that never started was published as a finished run — the tile now reads "
        f"'{after['total']} investigated' for a window nothing was read in: {after}"
    )


async def test_a_caller_that_walks_away_mid_planning_does_not_wedge_the_sweep(
    stalled_settings: Settings,
) -> None:
    """The single-flight claim must not outlive the request that made it.

    ``start_auto_triage`` claims the slot with ``status.active = True`` before its
    first await and releases it on every failure arm — except the one that is not
    an ``Exception``. ``CancelledError`` is a ``BaseException``, so a caller that
    goes away mid-planning (tab closed, the SPA unmounting its abort controller,
    the server shutting down) sails past every arm and leaves the claim set. From
    then on every Bulk Investigate answers "already running", the scheduler's
    backlog-drain sweep no-ops at its own ``if status.active`` gate
    (``soc_ai/webui/autotriage.py``), and ``GET /auto-triage`` reports a sweep
    that does not exist — until the process restarts.

    The bounded planning wait introduced by D12 is precisely the window a
    navigate-away lands in. Same mechanism, same fix, one file over in
    ``soc_ai/webui/backtest.py``; see
    ``test_a_caller_that_walks_away_mid_sample_does_not_wedge_the_slot`` in
    ``tests/test_backtest.py``.
    """
    import asyncio

    from soc_ai.api.webui.routes_autotriage import AutoTriageIn, start_auto_triage
    from soc_ai.webui import autotriage as at

    planning = anyio.Event()

    class _NeverAnswers:
        """The tarpit: the connection is accepted, the search is never answered."""

        async def search(self, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
            planning.set()
            await anyio.sleep_forever()
            return _es_ok()

    state = SimpleNamespace(settings=stalled_settings, elastic=_NeverAnswers())
    request = cast("Request", _StubRequest(state))
    task = asyncio.create_task(start_auto_triage(request, AutoTriageIn(range="24h")))
    with anyio.fail_after(5):
        await planning.wait()
    assert at.get_status(state).active is True, "the slot was never claimed — test is vacuous"

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert at.get_status(state).active is False, (
        "the single-flight claim survived the cancelled request — every later Bulk "
        "Investigate answers 'already running', the scheduled sweep no-ops, and the "
        "console reports a run that is gone, until the process restarts"
    )


# ---------------------------------------------------------------------------
# 3. Control — the guards must not fire on a healthy grid
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("panel", _PANELS, ids=_PANEL_IDS)
def test_a_healthy_grid_still_answers_each_panel(settings_kratos: Settings, panel: _Panel) -> None:
    """Without this the fix could be "always 503" and the suite would stay green."""
    for client in _client(settings_kratos, es_search=_es_ok):
        resp = client.get(panel.path, params=panel.params)
        assert resp.status_code == panel.healthy_status


@pytest.fixture
def busy_grid_settings(settings_kratos: Settings) -> Settings:
    """A budget with room to be slow INSIDE, for the over-correction control.

    ``stalled_settings`` squeezes the budget to its 1 s floor, which is right for
    "did the wrapper fire at all" and wrong here: this test needs a read that is
    slow but comfortably inside the bound, and at a 1 s budget the gap between
    "slow" and "expired" is smaller than a loaded CI box's scheduling noise. The
    assertions still read the budget off this object rather than hardcoding it.
    """
    return settings_kratos.model_copy(update={"webui_grid_timeout_s": 3})


@pytest.mark.parametrize("action", _ACTIONS, ids=[a.id for a in _ACTIONS])
def test_a_slow_but_working_grid_is_not_an_outage(
    busy_grid_settings: Settings, action: _Action
) -> None:
    """The over-correction control, and the reason each bound sits where it does.

    A grid can be slow and completely healthy — a busy cluster answers in
    seconds, not milliseconds — and a budget that fires on that turns every busy
    afternoon into an outage banner. So the crossing case is tested explicitly:
    every read here answers, late but inside the budget, and every action must
    come back with its ordinary healthy answer.

    This is also why the backtest bound wraps the SAMPLING SEARCH rather than
    ``POST /backtest``: the replay it launches is N full LLM investigations over
    a window up to a year wide, and a console budget across the whole job would
    fail a legitimately long-running one. Bound the read, not the work.
    """
    budget = busy_grid_settings.webui_grid_timeout_s
    # Comfortably inside the tightest bound this action passes through, but far
    # from instant: an implementation that answered only because nothing ever
    # blocked would not be exercised. See ``slow_read_share``.
    slow_s = budget * action.slow_read_share

    async def _slow_but_fine(**_kwargs: Any) -> dict[str, Any]:
        await anyio.sleep(slow_s)
        return _es_ok()

    with patch("soc_ai.webui.probes.probe_model_fitness", _fake_probe_model_fitness):
        for client in _client(busy_grid_settings, es_search=_slow_but_fine):
            resp = client.request(action.method, action.path, json=action.body)

    assert resp.status_code == 200, (
        f"{action.id} reported a working-but-slow grid as a failure ({resp.status_code}) — "
        f"the bound fired at webui_grid_timeout_s={budget} on a read that answered"
    )
    if action.id == "test-es":
        assert resp.json()["ok"] is True, "a slow grid that answered is a passing connection test"


def test_planning_that_outruns_its_shared_budget_still_does_not_cry_outage(
    stalled_settings: Settings,
) -> None:
    """The known-coarse edge of the auto-triage bound, pinned rather than hidden.

    One wrapper sits over a fan-out: ``plan_targets`` reads groups per severity
    (two searches each with ``webui_extra_detections`` on) and then events per
    group, all sharing a single ``webui_grid_timeout_s``. So a grid that answers
    every read — late, but inside the per-read budget the alerts console gives one
    of the very same queries — can still spend the planner's whole allowance. The
    right shape is a per-read bound beside the loop in ``soc_ai/webui/autotriage.py``,
    which this batch does not own.

    What matters until then is WHAT gets said, and that is what this asserts. The
    grid here is demonstrably up: every search returns. So the answer may not claim
    an outage. It must name the budget it ran out of, offer the move that fits
    inside it, and leave the dashboard's sweep marks alone — a sweep that never
    started is not a sweep that came back blind, and the tile must not report one
    as the other.

    If a per-read bound lands in autotriage.py, this test starts failing on the
    status code: delete it, because the case it pins stops existing.
    """
    budget = stalled_settings.webui_grid_timeout_s
    # Each read answers well inside a single console budget; four of them do not.
    slow_s = budget * 0.5

    async def _slow_but_fine(**_kwargs: Any) -> dict[str, Any]:
        await anyio.sleep(slow_s)
        return _es_ok()

    for client in _client(stalled_settings, es_search=_slow_but_fine):
        resp = client.post("/api/v1/auto-triage", json={"range": "24h"})
        after = client.get("/api/v1/auto-triage").json()

    assert resp.status_code == 503
    hint = resp.json()["detail"]["hint"]
    assert f"{budget}s" in hint, f"the refusal does not say what budget it ran out of: {hint!r}"
    assert "narrow" in hint.lower(), f"the refusal offers no move that would fit: {hint!r}"
    # The grid answered every query. Nothing here may be written down as a blind
    # sweep, and nothing may be written down as a completed one either.
    assert after["degraded"] is False, (
        "a planning pass that ran out of budget on a grid that ANSWERED was published as "
        f"a degraded sweep — the dashboard tile now reports an outage that isn't: {after}"
    )
    assert after["active"] is False
    assert after["finished_at"] is None
