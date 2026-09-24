"""Unit tests for the onboarding preflight rows added to the doctor."""

from __future__ import annotations

import json
import socket
import ssl
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from elastic_transport import ObjectApiResponse
from soc_ai import doctor
from soc_ai.config import DEFAULT_ALERTS_QUERY, Settings
from soc_ai.so_client.elastic import EsSearchResult, GridPartialResultsError
from soc_ai.so_client.oql import filter_to_dsl, parse_oql
from soc_ai.webui import alerts_query as aq


class _FakeSecurity:
    # `resp` also accepts a real ObjectApiResponse (see
    # test_audit_grant_pass_unwraps_object_api_response) — widened from
    # dict[str, Any] to cover both shapes the real `has_privileges` can answer.
    def __init__(self, resp: Any = None, exc: Exception | None = None) -> None:
        self._resp, self._exc = resp, exc
        self.calls: list[dict[str, Any]] = []

    async def has_privileges(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if self._exc is not None:
            raise self._exc
        assert self._resp is not None
        return self._resp


class _FakeInner:
    """``_client`` double — only ``security`` lives here now.

    The index-pattern coverage check used to reach through here for a raw
    ``.count()`` too, but now goes through ``ElasticClient.search`` (see
    ``_FakeSearch`` below) so it inherits the partial-read guard; only
    ``check_audit_write_privileges`` still has a legitimate reason to reach
    past the wrapper, for ``security.has_privileges``.
    """

    def __init__(self, security: _FakeSecurity | None = None) -> None:
        self.security = security if security is not None else _FakeSecurity()


class _FakeSearch:
    """``ElasticClient.search`` double for the index-pattern coverage check.

    Callable (mimics a bound method): reads the requested ``event.dataset``
    term out of the query and answers with a real ``EsSearchResult`` carrying
    the scripted count for that dataset (0 for anything unscripted). Records
    every call verbatim so tests can pin the per-dataset request shape. With
    ``exc`` set, every call raises it instead — used both for a generic
    transport failure and for a scripted ``GridPartialResultsError``.
    """

    def __init__(self, counts: dict[str, int], *, exc: Exception | None = None) -> None:
        self._counts = counts
        self._exc = exc
        self.calls: list[dict[str, Any]] = []

    async def __call__(self, index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        self.calls.append({"index": index, "query": query, **kwargs})
        if self._exc is not None:
            raise self._exc
        dataset = query["term"]["event.dataset"]
        return EsSearchResult(total=self._counts.get(dataset, 0), took_ms=1)


class _FakeElastic:
    def __init__(
        self, security: _FakeSecurity | None = None, search: _FakeSearch | None = None
    ) -> None:
        self._client = _FakeInner(security)
        self.search = search if search is not None else _FakeSearch({})
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True


def _patch_elastic(monkeypatch: pytest.MonkeyPatch, fake: _FakeElastic) -> None:
    monkeypatch.setattr("soc_ai.doctor.ElasticClient", lambda _s: fake)


_ALL_SIX_PRIVILEGES = {
    "auto_configure",
    "create_index",
    "index",
    "read",
    "view_index_metadata",
    "write",
}


def _today_index_name() -> str:
    return f"soc-ai-audit-{datetime.now(tz=UTC):%Y.%m.%d}"


async def test_audit_grant_pass(monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings) -> None:
    security = _FakeSecurity(resp={"has_all_requested": True})
    fake = _FakeElastic(security)
    _patch_elastic(monkeypatch, fake)
    result = await doctor.check_audit_write_privileges(settings_kratos)
    assert result.status == "PASS"
    assert fake.closed
    assert len(security.calls) == 1
    index_arg = security.calls[0]["index"][0]
    assert index_arg["names"] == [_today_index_name()]
    assert set(index_arg["privileges"]) == _ALL_SIX_PRIVILEGES


async def test_audit_grant_missing_names_the_fix(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    index_name = _today_index_name()
    resp = {
        "has_all_requested": False,
        "index": {
            index_name: {
                "auto_configure": True,
                "create_index": True,
                "index": True,
                "read": True,
                "view_index_metadata": True,
                "write": False,
            }
        },
    }
    fake = _FakeElastic(_FakeSecurity(resp=resp))
    _patch_elastic(monkeypatch, fake)
    result = await doctor.check_audit_write_privileges(settings_kratos)
    assert result.status == "FAIL"
    assert "write" in result.detail
    assert "fail-closed" in result.detail
    assert "setup-audit-index.sh" in result.hint


async def test_audit_grant_read_only_missing_warns(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    index_name = _today_index_name()
    resp = {
        "has_all_requested": False,
        "index": {
            index_name: {
                "auto_configure": True,
                "create_index": True,
                "index": True,
                "read": False,
                "view_index_metadata": True,
                "write": True,
            }
        },
    }
    fake = _FakeElastic(_FakeSecurity(resp=resp))
    _patch_elastic(monkeypatch, fake)
    result = await doctor.check_audit_write_privileges(settings_kratos)
    assert result.status == "WARN"
    assert "read" in result.detail
    assert "chain" in result.detail


async def test_audit_grant_unexpected_shape_warns(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    fake = _FakeElastic(_FakeSecurity(resp={"unexpected_key": True}))
    _patch_elastic(monkeypatch, fake)
    result = await doctor.check_audit_write_privileges(settings_kratos)
    assert result.status == "WARN"
    assert "unexpected" in result.detail.lower()


async def test_audit_grant_api_unavailable_warns(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    fake = _FakeElastic(_FakeSecurity(exc=RuntimeError("security disabled")))
    _patch_elastic(monkeypatch, fake)
    result = await doctor.check_audit_write_privileges(settings_kratos)
    assert result.status == "WARN"
    assert "setup-audit-index.sh" in result.hint


async def test_audit_grant_pass_unwraps_object_api_response(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """PASS path's ``.body`` unwrap, pinned against a REAL ObjectApiResponse —
    every other audit-grant test above doubles it as a plain dict."""
    index_name = _today_index_name()
    body = {
        "has_all_requested": True,
        "index": {index_name: dict.fromkeys(_ALL_SIX_PRIVILEGES, True)},
    }
    security = _FakeSecurity(resp=ObjectApiResponse(body=body, meta=None))
    fake = _FakeElastic(security)
    _patch_elastic(monkeypatch, fake)
    result = await doctor.check_audit_write_privileges(settings_kratos)
    assert result.status == "PASS"
    assert fake.closed


# ── index-pattern dataset coverage (the .ds-* narrowing trap) ────────────────


async def test_coverage_narrowed_pattern_warns(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """Alerts present, auth+syslog both zero — the exact ``.ds-*`` narrowing shape."""
    search = _FakeSearch({"suricata.alert": 4200, "system.auth": 0, "system.syslog": 0})
    fake = _FakeElastic(search=search)
    _patch_elastic(monkeypatch, fake)
    result = await doctor.check_index_pattern_coverage(settings_kratos)
    assert result.status == "WARN"
    assert "auth/syslog" in result.detail
    assert "logs-*" in result.hint


async def test_coverage_healthy_passes_and_pins_call_shape(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    search = _FakeSearch({"suricata.alert": 4200, "system.auth": 117, "system.syslog": 9000})
    fake = _FakeElastic(search=search)
    _patch_elastic(monkeypatch, fake)
    result = await doctor.check_index_pattern_coverage(settings_kratos)
    assert result.status == "PASS"
    assert "4200" in result.detail
    assert "117" in result.detail
    assert "9000" in result.detail
    assert fake.closed
    # Pin the wiring: three searches, one per _COVERAGE_DATASETS entry (order
    # is not pinned — they run concurrently via asyncio.gather), each a
    # size=0/track_total_hits=True term-search scoped to the configured
    # pattern. ignore_unavailable/allow_no_indices are no longer this check's
    # business — ElasticClient.search sets them internally.
    assert len(search.calls) == 3
    called_datasets = {call["query"]["term"]["event.dataset"] for call in search.calls}
    assert called_datasets == set(doctor._COVERAGE_DATASETS)
    for call in search.calls:
        assert call["index"] == settings_kratos.events_index_pattern
        assert call["size"] == 0
        assert call["track_total_hits"] is True


async def test_coverage_all_zero_warns(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    search = _FakeSearch({})  # every dataset defaults to 0
    fake = _FakeElastic(search=search)
    _patch_elastic(monkeypatch, fake)
    result = await doctor.check_index_pattern_coverage(settings_kratos)
    assert result.status == "WARN"
    assert "no suricata/auth/syslog events" in result.detail


async def test_coverage_zero_alerts_with_auth_syslog_passes_with_note(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """Alerts empty but auth/syslog present isn't a narrowing symptom — PASS,
    but call out that the triage queue (which reads suricata.alert) is empty."""
    search = _FakeSearch({"suricata.alert": 0, "system.auth": 117, "system.syslog": 9000})
    fake = _FakeElastic(search=search)
    _patch_elastic(monkeypatch, fake)
    result = await doctor.check_index_pattern_coverage(settings_kratos)
    assert result.status == "PASS"
    assert "no suricata.alert events" in result.detail
    assert "triage queue will be empty" in result.detail


async def test_coverage_count_error_warns(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    search = _FakeSearch({}, exc=RuntimeError("no such index [logs-*]"))
    fake = _FakeElastic(search=search)
    _patch_elastic(monkeypatch, fake)
    result = await doctor.check_index_pattern_coverage(settings_kratos)
    assert result.status == "WARN"
    assert result.hint.startswith("Fix Elasticsearch connectivity first")
    assert fake.closed  # cleanup still runs on the exception path


async def test_coverage_partial_grid_read_warns(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """The half-read-grid regression: failed/unassigned shards must WARN
    honestly, never get misdiagnosed as a narrowed EVENTS_INDEX_PATTERN."""
    exc = GridPartialResultsError(
        "partial search results from logs-*: 2 of 5 shards failed",
        shards_failed=2,
        shards_total=5,
    )
    search = _FakeSearch({}, exc=exc)
    fake = _FakeElastic(search=search)
    _patch_elastic(monkeypatch, fake)
    result = await doctor.check_index_pattern_coverage(settings_kratos)
    assert result.status == "WARN"
    assert "partial" in result.detail
    # Pins the except-arm ORDERING this test exists to protect: a swapped
    # order (checking the narrowed-pattern shape before the partial-read
    # guard) would stay green on the substring checks above alone.
    assert "counts are unreliable" in result.detail
    assert "narrowed" not in result.detail
    # The remedy names shard health, not connectivity: this grid answered, in
    # milliseconds, off the shards it still has. Sending the admin to check the
    # connection is the same wrong-building mistake one line up in the detail.
    assert "shard health" in result.hint
    assert "connectivity" not in result.hint
    assert fake.closed


# ── upstream reachability (DNS vs TCP/firewall vs TLS trust) ─────────────────
#
# Module-local doubles — deliberately NOT sharing _FakeElastic/_FakeSearch
# above: this check never touches ElasticClient, it goes straight at the
# `socket`/`ssl` layer that _classify_endpoint (soc_ai/doctor.py) calls
# through `asyncio.to_thread`, so the doubles here patch `socket.getaddrinfo`,
# `socket.create_connection`, and `doctor._tls_handshake` instead.
#
# settings_kratos targets (see tests/conftest.py::_base_settings_kwargs):
#   SO reachability      https://so.example.com        (so_verify_ssl=False)
#   ES reachability       https://so.example.com:9200   (es_verify_ssl=True, default)
#   gateway reachability  http://localhost:4000         (litellm_verify_ssl=True, default)
# So ES is the one https+verify-on target, SO is https-but-verify-off, and
# gateway is the one plain-http target — exactly the three shapes the tests
# below need to tell apart.


class _FakeConnectedSocket:
    """``socket.create_connection``'s return value — just enough to be a
    context manager ``_classify_endpoint`` can pass to ``_tls_handshake``."""

    def __enter__(self) -> _FakeConnectedSocket:
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


def _fake_getaddrinfo(host: str, port: int, *args: Any, **kwargs: Any) -> list[Any]:
    """Resolves anything to a single, made-up address.

    _classify_endpoint only calls getaddrinfo to CLASSIFY a DNS failure — it
    never reads the returned addresses (create_connection is handed the
    hostname, not a resolved address; see
    test_reachability_connects_by_hostname_not_resolved_address below) — so
    this only has to not raise.
    """
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (host, port))]


async def test_reachability_dns_failure_all_fail(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    def _raise_gaierror(*args: Any, **kwargs: Any) -> list[Any]:
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr("socket.getaddrinfo", _raise_gaierror)
    results = await doctor.check_upstream_reachability(settings_kratos)
    assert len(results) == 3
    assert [r.status for r in results] == ["FAIL", "FAIL", "FAIL"]
    for r in results:
        assert "resolve" in r.hint.lower() or "DNS" in r.detail


async def test_reachability_dns_label_too_long_is_dns_kind(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """getaddrinfo raises UnicodeError (not gaierror) for a >63-char DNS
    label — a shape pydantic's AnyHttpUrl accepts without complaint. Without
    the UnicodeError arm, one such URL falls through to the generic OSError
    "reach" arm and collapses all three rows into an undifferentiated FAIL
    instead of naming it a DNS problem."""

    def _raise_unicode_error(*args: Any, **kwargs: Any) -> list[Any]:
        raise UnicodeError("encoding with 'idna' codec failed")

    monkeypatch.setattr("socket.getaddrinfo", _raise_unicode_error)
    results = await doctor.check_upstream_reachability(settings_kratos)
    assert len(results) == 3
    assert [r.status for r in results] == ["FAIL", "FAIL", "FAIL"]
    for r in results:
        assert "resolve" in r.hint.lower() or "DNS" in r.detail


async def test_reachability_connection_refused_names_firewall(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    def _raise_refused(*args: Any, **kwargs: Any) -> Any:
        raise ConnectionRefusedError(111, "Connection refused")

    monkeypatch.setattr("socket.getaddrinfo", _fake_getaddrinfo)
    monkeypatch.setattr("socket.create_connection", _raise_refused)
    results = await doctor.check_upstream_reachability(settings_kratos)
    assert len(results) == 3
    assert all(r.status == "FAIL" for r in results)

    by_name = {r.name: r for r in results}
    # SO/ES sit behind the SO firewall — keep the pinhole wording naming ES's
    # port specifically.
    assert "firewall" in by_name["SO reachability"].hint.lower()
    assert "firewall" in by_name["ES reachability"].hint.lower()
    # The gateway is a different service entirely — sending an operator to
    # pinhole the SO firewall for a dead LiteLLM box would point nowhere.
    assert "firewall" not in by_name["gateway reachability"].hint.lower()


async def test_reachability_all_good(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    def _fake_create_connection(address: Any, timeout: float | None = None) -> _FakeConnectedSocket:
        return _FakeConnectedSocket()

    def _fake_tls_handshake(sock: Any, host: str) -> None:
        return None

    monkeypatch.setattr("socket.getaddrinfo", _fake_getaddrinfo)
    monkeypatch.setattr("socket.create_connection", _fake_create_connection)
    monkeypatch.setattr("soc_ai.doctor._tls_handshake", _fake_tls_handshake)

    results = await doctor.check_upstream_reachability(settings_kratos)
    assert [r.status for r in results] == ["PASS", "PASS", "PASS"]

    by_name = {r.name: r for r in results}
    # ES is https with es_verify_ssl=True (settings_kratos default) — the one
    # target that should come back noting TLS was actually verified.
    assert "TLS verifies" in by_name["ES reachability"].detail
    # gateway is plain http (litellm_base_url="http://localhost:4000") — must
    # never claim a TLS verification that never happened.
    assert "TLS" not in by_name["gateway reachability"].detail
    # SO is https but so_verify_ssl=False in settings_kratos — verified is
    # off, so this must not claim TLS either.
    assert "TLS" not in by_name["SO reachability"].detail


async def test_reachability_tls_verification_failure(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    def _fake_create_connection(address: Any, timeout: float | None = None) -> _FakeConnectedSocket:
        return _FakeConnectedSocket()

    def _raise_tls(sock: Any, host: str) -> None:
        raise ssl.SSLCertVerificationError("certificate verify failed: self-signed certificate")

    monkeypatch.setattr("socket.getaddrinfo", _fake_getaddrinfo)
    monkeypatch.setattr("socket.create_connection", _fake_create_connection)
    monkeypatch.setattr("soc_ai.doctor._tls_handshake", _raise_tls)

    results = await doctor.check_upstream_reachability(settings_kratos)
    by_name = {r.name: r for r in results}

    es = by_name["ES reachability"]  # https + es_verify_ssl=True → handshake runs, and fails
    assert es.status == "FAIL"
    assert "ES_CA_BUNDLE" in es.hint or "ES_VERIFY_SSL" in es.hint

    # SO is https too, but so_verify_ssl=False in settings_kratos — pin that
    # the handshake (which would raise for ANY host, per the stub above) is
    # never even attempted when verify is off, so this still PASSes.
    so = by_name["SO reachability"]
    assert so.status == "PASS"

    # gateway is plain http in settings_kratos, so its own "tls" hint never
    # gets exercised above (the handshake is scheme-gated and never runs for
    # http). Flip it to https+verify locally — without touching the shared
    # fixture — to pin that a gateway TLS failure names the real LiteLLM knob
    # and never invents a LITELLM_CA_BUNDLE that doesn't exist in Settings.
    gw_settings = settings_kratos.model_copy(
        update={
            "litellm_base_url": "https://gateway.example.com:4000",
            "litellm_verify_ssl": True,
        }
    )
    gw_results = await doctor.check_upstream_reachability(gw_settings)
    gw = {r.name: r for r in gw_results}["gateway reachability"]
    assert gw.status == "FAIL"
    assert "LITELLM_VERIFY_SSL" in gw.hint
    assert "CA_BUNDLE" not in gw.hint


async def test_reachability_timeout_fails(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    def _raise_timeout(*args: Any, **kwargs: Any) -> Any:
        raise TimeoutError("timed out")

    monkeypatch.setattr("socket.getaddrinfo", _fake_getaddrinfo)
    monkeypatch.setattr("socket.create_connection", _raise_timeout)

    results = await doctor.check_upstream_reachability(settings_kratos)
    assert len(results) == 3
    assert all(r.status == "FAIL" for r in results)
    by_name = {r.name: r for r in results}
    for slug, name in (
        ("so", "SO reachability"),
        ("es", "ES reachability"),
        ("gateway", "gateway reachability"),
    ):
        result = by_name[name]
        assert "timed out" in result.detail
        assert result.hint == doctor._REACH_HINTS[(slug, "reach")]


async def test_reachability_probes_run_concurrently(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """Pins the concurrency this check exists to guarantee: a 3-party barrier
    inside ``create_connection`` requires all three probes to have STARTED
    before any of them can return. Run serially, the first call would block
    alone until the barrier's timeout and blow up with BrokenBarrierError —
    a latency-insensitive, non-flaky way to pin "all three began before any
    returned" without asserting on wall-clock durations.
    """
    barrier = threading.Barrier(3, timeout=2.0)

    def _fake_create_connection(address: Any, timeout: float | None = None) -> _FakeConnectedSocket:
        barrier.wait()
        return _FakeConnectedSocket()

    monkeypatch.setattr("socket.getaddrinfo", _fake_getaddrinfo)
    monkeypatch.setattr("socket.create_connection", _fake_create_connection)
    monkeypatch.setattr("soc_ai.doctor._tls_handshake", lambda sock, host: None)

    results = await doctor.check_upstream_reachability(settings_kratos)
    assert [r.status for r in results] == ["PASS", "PASS", "PASS"]


async def test_reachability_connects_by_hostname_not_resolved_address(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """Pins the infos[0] regression: create_connection must be called with
    the ORIGINAL (host, port) from the URL, not a resolved address literal.

    getaddrinfo is stubbed to return TWO addresses (as a dual-stack host
    would — an AAAA entry sorted first, then an A entry) to prove neither one
    is what gets connected to: create_connection does its own resolution and
    address iteration internally (the same as the app's real HTTP client), so
    _classify_endpoint must hand it the hostname, never pin the connect to
    whichever address getaddrinfo happened to sort first.
    """
    calls: list[tuple[str, int]] = []

    def _fake_getaddrinfo_dual_stack(host: str, port: int, *args: Any, **kwargs: Any) -> list[Any]:
        return [
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("2001:db8::1", port, 0, 0),
            ),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("203.0.113.1", port)),
        ]

    def _fake_create_connection(address: Any, timeout: float | None = None) -> _FakeConnectedSocket:
        calls.append(address)
        return _FakeConnectedSocket()

    monkeypatch.setattr("socket.getaddrinfo", _fake_getaddrinfo_dual_stack)
    monkeypatch.setattr("socket.create_connection", _fake_create_connection)
    monkeypatch.setattr("soc_ai.doctor._tls_handshake", lambda sock, host: None)

    results = await doctor.check_upstream_reachability(settings_kratos)
    assert [r.status for r in results] == ["PASS", "PASS", "PASS"]

    # Every create_connection call got the (hostname, port) straight from the
    # target URL — never the fake resolved IPs getaddrinfo returned above.
    assert len(calls) == 3
    assert set(calls) == {("so.example.com", 443), ("so.example.com", 9200), ("localhost", 4000)}


async def test_reachability_non_cert_ssl_error_is_tls_kind(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """A plain ssl.SSLError (e.g. WRONG_VERSION_NUMBER — TCP connected but the
    peer isn't speaking TLS at all) must classify as "tls", not fall through
    to the generic OSError "reach" arm and send the operator to check
    firewalls for what is actually a protocol mismatch."""

    def _fake_create_connection(address: Any, timeout: float | None = None) -> _FakeConnectedSocket:
        return _FakeConnectedSocket()

    def _raise_non_cert_tls_error(sock: Any, host: str) -> None:
        raise ssl.SSLError("WRONG_VERSION_NUMBER")

    monkeypatch.setattr("socket.getaddrinfo", _fake_getaddrinfo)
    monkeypatch.setattr("socket.create_connection", _fake_create_connection)
    monkeypatch.setattr("soc_ai.doctor._tls_handshake", _raise_non_cert_tls_error)

    results = await doctor.check_upstream_reachability(settings_kratos)
    by_name = {r.name: r for r in results}

    es = by_name["ES reachability"]  # https + es_verify_ssl=True → handshake runs, raises
    assert es.status == "FAIL"
    assert "handshake failed" in es.detail
    assert "http://" in es.hint
    assert "firewall" not in es.hint.lower()


async def test_reachability_es_multi_host_note_on_pass(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """A green ES row must not read as "the whole cluster is reachable" when
    it only ever probed the first of several configured es_hosts — settings_kratos
    itself only has one, so this overrides es_hosts locally to exercise the
    len(es_hosts) > 1 branch."""

    def _fake_create_connection(address: Any, timeout: float | None = None) -> _FakeConnectedSocket:
        return _FakeConnectedSocket()

    monkeypatch.setattr("socket.getaddrinfo", _fake_getaddrinfo)
    monkeypatch.setattr("socket.create_connection", _fake_create_connection)
    monkeypatch.setattr("soc_ai.doctor._tls_handshake", lambda sock, host: None)

    settings = settings_kratos.model_copy(
        update={
            "es_hosts": [
                "https://es1.example.com:9200",
                "https://es2.example.com:9200",
                "https://es3.example.com:9200",
            ]
        }
    )
    results = await doctor.check_upstream_reachability(settings)
    es = {r.name: r for r in results}["ES reachability"]
    assert es.status == "PASS"
    assert "first of 3 es_hosts" in es.detail


def test_reach_hints_cover_every_target_and_failure_kind() -> None:
    """A missing (slug, kind) entry must fail HERE, in a fast unit test — not
    surface as a runtime KeyError that takes out an entire doctor row (and,
    since check_upstream_reachability has no per-target isolation of its
    own, the other two rows alongside it)."""
    expected = {
        (slug, kind) for slug in ("so", "es", "gateway") for kind in ("dns", "tls", "reach")
    }
    assert set(doctor._REACH_HINTS) == expected


# ── alerts-feed filter vs how the grid labels alerts ─────────────────────────


def _source_dsl(label: str) -> dict[str, Any]:
    """The clause ``build_filter`` puts in ``must[0]`` for one alert-label OQL."""
    return filter_to_dsl(parse_oql(label).filter_)


class _FakeAlertFilterSearch:
    """``ElasticClient.search`` double for the alerts-feed-filter check.

    Scripted BY LABEL rather than by call order, because the check issues its
    probes concurrently and the order is not a contract. Each scripted label is
    translated through the same ``parse_oql``/``filter_to_dsl`` path the real
    filter builder uses, and an incoming call is attributed to whichever
    label's clause it carries in ``must[0]``; an unscripted label answers 0.
    With ``exc`` set, every call raises it instead.
    """

    def __init__(
        self,
        counts: dict[str, int],
        *,
        exc: Exception | None = None,
        datasets: dict[str, dict[str, int]] | None = None,
        truncated: set[str] | None = None,
    ) -> None:
        self._by_clause = {
            json.dumps(_source_dsl(label), sort_keys=True): total for label, total in counts.items()
        }
        # Per-label ``event.dataset`` breakdown, the class dimension the
        # zero-coverage half of the check reads. Unscripted labels answer with
        # no buckets, which is "this label saw nothing" and never a blind spot.
        self._classes_by_clause = {
            json.dumps(_source_dsl(label), sort_keys=True): buckets
            for label, buckets in (datasets or {}).items()
        }
        # Labels whose terms aggregation the grid cut short.
        self._truncated = {
            json.dumps(_source_dsl(label), sort_keys=True) for label in (truncated or set())
        }
        self._exc = exc
        self.calls: list[dict[str, Any]] = []

    async def __call__(self, index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        self.calls.append({"index": index, "query": query, **kwargs})
        if self._exc is not None:
            raise self._exc
        clause = json.dumps(query["bool"]["must"][0], sort_keys=True)
        buckets = [
            {"key": ds, "doc_count": n} for ds, n in self._classes_by_clause.get(clause, {}).items()
        ]
        return EsSearchResult(
            total=self._by_clause.get(clause, 0),
            took_ms=1,
            aggregations={
                aq.ALERT_CLASS_AGG: {
                    "buckets": buckets,
                    "sum_other_doc_count": 1 if clause in self._truncated else 0,
                }
            },
        )


def _alerts_settings(settings: Settings, query: str) -> Settings:
    return settings.model_copy(update={"webui_alerts_query": query})


async def test_alerts_filter_matches_nothing_while_another_label_does(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """The dogfood shape: the configured filter is empty while the grid is not.

    An alerts feed that finds nothing because it is asking the wrong question
    is indistinguishable from a quiet network, which is the failure this check
    exists to name. It must say WHICH label would have found the alerts.
    """
    search = _FakeAlertFilterSearch({"tags:alerts": 22, "event.kind:alert": 25})
    fake = _FakeElastic(search=search)
    _patch_elastic(monkeypatch, fake)
    result = await doctor.check_alerts_feed_filter(_alerts_settings(settings_kratos, "tags:alert"))
    assert result.status == "WARN"
    assert "tags:alert" in result.detail
    assert "event.kind:alert" in result.detail
    assert "25" in result.detail
    assert "event.kind:alert" in result.hint
    assert "WEBUI_ALERTS_QUERY" in result.hint
    # The sentence is the whole point of the row: an empty queue that the
    # operator can tell apart from a quiet network. Asserting only WARN passes
    # against the far-behind wording too, which never says the queue is empty.
    assert "The grid is not quiet" in result.detail
    assert fake.closed


async def test_alerts_filter_matching_nothing_warns_however_few_the_alternative_found(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """Zero is a different fact from few, and the margin must not swallow it.

    A single ratio-and-margin rule reads three alerts against zero as ordinary
    spread and PASSes. Nothing about the queue is ordinary: it is empty, alerts
    exist, and the analyst sees an all-clear.
    """
    search = _FakeAlertFilterSearch({"tags:alerts": 3})
    fake = _FakeElastic(search=search)
    _patch_elastic(monkeypatch, fake)
    result = await doctor.check_alerts_feed_filter(_alerts_settings(settings_kratos, "tags:alert"))
    assert result.status == "WARN"
    assert "tags:alerts" in result.hint


async def test_alerts_filter_far_behind_an_alternative_warns(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """Two matches is not zero, and it is still the wrong question.

    The over-narrow guard: a check that only fires on an exactly-empty feed
    would have called the measured grid healthy at 2 of 25.
    """
    search = _FakeAlertFilterSearch({"tags:alert": 2, "tags:alerts": 22, "event.kind:alert": 25})
    fake = _FakeElastic(search=search)
    _patch_elastic(monkeypatch, fake)
    result = await doctor.check_alerts_feed_filter(_alerts_settings(settings_kratos, "tags:alert"))
    assert result.status == "WARN"
    assert "event.kind:alert" in result.hint


async def test_alerts_filter_ahead_of_every_alternative_passes_and_pins_call_shape(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    union = "tags:alert OR tags:alerts OR event.kind:alert"
    search = _FakeAlertFilterSearch(
        {union: 25, "tags:alert": 2, "tags:alerts": 22, "event.kind:alert": 25}
    )
    fake = _FakeElastic(search=search)
    _patch_elastic(monkeypatch, fake)
    settings = _alerts_settings(settings_kratos, union)
    result = await doctor.check_alerts_feed_filter(settings)
    assert result.status == "PASS"
    assert "25" in result.detail
    assert fake.closed
    # Pin the wiring: one size=0/track_total_hits=True search per probed label,
    # each scoped to the configured index pattern, each carrying the feed's own
    # synthetic-row exclusion so the counts are the feed's counts and not a
    # looser approximation of them.
    assert len(search.calls) == 1 + len(aq.ALERT_LABEL_CANDIDATES)
    for call in search.calls:
        assert call["index"] == settings.events_index_pattern
        assert call["size"] == 0
        assert call["track_total_hits"] is True
        assert {"exists": {"field": "synth.scenario_id"}} in call["query"]["bool"]["must_not"]


async def test_alerts_filter_on_a_quiet_grid_passes_with_a_note(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """No label finds anything, so nothing is misconfigured. The grid is quiet.

    The over-correction guard. Reporting a problem here would train operators
    to ignore the row on every idle grid, which is how a real mismatch gets
    scrolled past.
    """
    search = _FakeAlertFilterSearch({})
    fake = _FakeElastic(search=search)
    _patch_elastic(monkeypatch, fake)
    result = await doctor.check_alerts_feed_filter(_alerts_settings(settings_kratos, "tags:alert"))
    assert result.status == "PASS"
    assert "No label found an alert" in result.detail
    assert "triage queue will be empty" in result.detail


async def test_alerts_filter_that_is_not_valid_oql_warns(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """A filter the query builder rejects empties the feed on every request."""
    search = _FakeAlertFilterSearch({})
    fake = _FakeElastic(search=search)
    _patch_elastic(monkeypatch, fake)
    result = await doctor.check_alerts_feed_filter(
        _alerts_settings(settings_kratos, "not_a_whitelisted_field:alert")
    )
    assert result.status == "WARN"
    assert "WEBUI_ALERTS_QUERY" in result.hint
    assert not search.calls  # rejected before any grid round trip


async def test_alerts_filter_count_error_warns(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    search = _FakeAlertFilterSearch({}, exc=RuntimeError("no such index [logs-*]"))
    fake = _FakeElastic(search=search)
    _patch_elastic(monkeypatch, fake)
    result = await doctor.check_alerts_feed_filter(_alerts_settings(settings_kratos, "tags:alert"))
    assert result.status == "WARN"
    assert result.hint.startswith("Fix Elasticsearch connectivity first")
    assert fake.closed


async def test_alerts_filter_partial_grid_read_warns(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """A half-read grid undercounts the configured filter as easily as an
    alternative, so it must never be reported as a filter mismatch."""
    exc = GridPartialResultsError(
        "partial search results from logs-*: 2 of 5 shards failed",
        shards_failed=2,
        shards_total=5,
    )
    search = _FakeAlertFilterSearch({}, exc=exc)
    fake = _FakeElastic(search=search)
    _patch_elastic(monkeypatch, fake)
    result = await doctor.check_alerts_feed_filter(_alerts_settings(settings_kratos, "tags:alert"))
    assert result.status == "WARN"
    assert "counts are unreliable" in result.detail
    assert "WEBUI_ALERTS_QUERY" not in result.hint
    assert result.hint.startswith("Fix Elasticsearch connectivity first")
    assert fake.closed


def _hint_filter(hint: str) -> str:
    """The exact OQL the hint tells the operator to set, lifted verbatim.

    A hint an operator has to interpret is a hint that gets interpreted
    differently, so this reads the sentence the way a reader would: take what
    follows ``WEBUI_ALERTS_QUERY=`` up to the end of that sentence (the next
    ``". "``). Field names carry dots but never a dot-then-space, so this
    never cuts the filter itself short.
    """
    _, _, tail = hint.partition("WEBUI_ALERTS_QUERY=")
    return tail.split(". ")[0].strip()


async def test_alerts_filter_hint_keeps_what_the_configured_filter_already_finds(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """The remedy must not cause the problem the check exists to detect.

    Measured on a live grid on 2026-09-05: ``tags:alert`` matched 2 documents
    and ``event.kind:alert`` matched 34, and the two sets were DISJOINT: the 2
    carried no ``event.kind`` at all, and they were that grid's DCSync
    detections, the highest-value alerts on it. A hint that says "set
    WEBUI_ALERTS_QUERY=event.kind:alert" gets followed literally, and following
    it drops those 2. A check that fires on a filter which hides alerts has to
    recommend a SUPERSET of the filter in place, not a swap.
    """
    search = _FakeAlertFilterSearch({"tags:alert": 2, "event.kind:alert": 34})
    fake = _FakeElastic(search=search)
    _patch_elastic(monkeypatch, fake)
    result = await doctor.check_alerts_feed_filter(_alerts_settings(settings_kratos, "tags:alert"))
    assert result.status == "WARN"
    recommended = _hint_filter(result.hint)
    # Pasteable and exact: the sentence names a value, and that value is OQL
    # the feed's own builder accepts.
    assert recommended
    dsl = filter_to_dsl(parse_oql(recommended).filter_)
    # The superset, proven on the query the recommendation compiles to: the
    # label in place and the label that finds more are both ORed in, so
    # nothing the operator can see today disappears when they follow the hint.
    assert dsl == {
        "bool": {
            "should": [{"term": {"tags": "alert"}}, {"term": {"event.kind": "alert"}}],
            "minimum_should_match": 1,
        }
    }


async def test_alerts_filter_hint_on_an_unparseable_filter_names_the_shipped_default(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """Nothing to widen when the filter in place matches nothing anywhere.

    A filter the query builder rejects empties the feed on every request, so
    there is no coverage to preserve, and carrying the broken text into an OR
    would hand back something that still does not parse. The hint still has to
    name a value the operator can paste, and the product ships the right one.
    """
    search = _FakeAlertFilterSearch({})
    fake = _FakeElastic(search=search)
    _patch_elastic(monkeypatch, fake)
    result = await doctor.check_alerts_feed_filter(
        _alerts_settings(settings_kratos, "not_a_whitelisted_field:alert")
    )
    assert result.status == "WARN"
    assert _hint_filter(result.hint) == DEFAULT_ALERTS_QUERY
    assert "not_a_whitelisted_field" not in result.hint


async def test_alerts_filter_warns_when_a_class_has_zero_coverage(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """A ratio cannot express an alert class the queue never sees.

    Measured on the deployed instance on 2026-09-06: the configured
    ``event.dataset:suricata.alert`` matched 1,441 documents in 24 hours and
    ``tags:alert`` matched 1,442, so every totals test on this row passes. The
    difference is not spread: it is Security Onion's Sigma engine, whose
    host-behavioural detections the configured filter matches NONE of. They have
    never reached the queue and the ratio can never say so.
    """
    search = _FakeAlertFilterSearch(
        {"event.dataset:suricata.alert": 1441, "tags:alert": 1442},
        datasets={
            "event.dataset:suricata.alert": {"suricata.alert": 1441},
            "tags:alert": {"suricata.alert": 1441, "sigma.alert": 1},
        },
    )
    fake = _FakeElastic(search=search)
    _patch_elastic(monkeypatch, fake)
    result = await doctor.check_alerts_feed_filter(
        _alerts_settings(settings_kratos, "event.dataset:suricata.alert")
    )
    assert result.status == "WARN"
    # Name the class. "Your filter is narrower" is not actionable; "the queue
    # has never seen a sigma.alert" is.
    assert "sigma.alert" in result.detail
    assert "tags:alert" in result.detail
    # And the remedy stays a widening, not a swap.
    assert _hint_filter(result.hint) == "event.dataset:suricata.alert OR tags:alert"


async def test_alerts_filter_zero_coverage_names_every_invisible_class(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """Two blind spots are two facts, and the operator gets both."""
    search = _FakeAlertFilterSearch(
        {"event.dataset:suricata.alert": 500, "tags:alert": 504, "event.kind:alert": 502},
        datasets={
            "event.dataset:suricata.alert": {"suricata.alert": 500},
            "tags:alert": {"suricata.alert": 500, "sigma.alert": 4},
            "event.kind:alert": {"suricata.alert": 500, "endpoint.alerts": 2},
        },
    )
    fake = _FakeElastic(search=search)
    _patch_elastic(monkeypatch, fake)
    result = await doctor.check_alerts_feed_filter(
        _alerts_settings(settings_kratos, "event.dataset:suricata.alert")
    )
    assert result.status == "WARN"
    assert "sigma.alert" in result.detail
    assert "endpoint.alerts" in result.detail
    # And ONE paste fixes both. This used to hand back only the label covering
    # the most documents, so following the hint cleared one blind spot and the
    # warning came back naming the other — which is what the home deployment
    # experienced on 2026-09-07. Widest first: tags:alert recovers 4,
    # event.kind:alert recovers 2.
    assert (
        _hint_filter(result.hint)
        == "event.dataset:suricata.alert OR tags:alert OR event.kind:alert"
    )


async def test_alerts_filter_one_blind_class_still_recommends_one_label(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """Negative control for the above: a single blind spot adds a single label.

    Covering every class in one paste must not turn into naming every candidate
    label the grid has. A label that recovers nothing has no business in a filter
    the operator is about to paste.
    """
    search = _FakeAlertFilterSearch(
        {"event.dataset:suricata.alert": 500, "tags:alert": 504, "event.kind:alert": 500},
        datasets={
            "event.dataset:suricata.alert": {"suricata.alert": 500},
            "tags:alert": {"suricata.alert": 500, "sigma.alert": 4},
            "event.kind:alert": {"suricata.alert": 500},
        },
    )
    _patch_elastic(monkeypatch, _FakeElastic(search=search))
    result = await doctor.check_alerts_feed_filter(
        _alerts_settings(settings_kratos, "event.dataset:suricata.alert")
    )
    assert result.status == "WARN"
    assert _hint_filter(result.hint) == "event.dataset:suricata.alert OR tags:alert"
    assert "event.kind:alert" not in _hint_filter(result.hint)


async def test_alerts_filter_covering_every_class_passes(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """Negative control: a genuinely well-configured filter still passes.

    The shipped default union sees every class an alternative sees, so there is
    no blind spot to report, and a check that WARNs here would train the operator
    to scroll past the row that matters.
    """
    union = DEFAULT_ALERTS_QUERY
    search = _FakeAlertFilterSearch(
        {union: 1442, "tags:alert": 1442, "tags:alerts": 0, "event.kind:alert": 2},
        datasets={
            union: {"suricata.alert": 1441, "sigma.alert": 1, "endpoint.alerts": 2},
            "tags:alert": {"suricata.alert": 1441, "sigma.alert": 1},
            "event.kind:alert": {"endpoint.alerts": 2},
        },
    )
    fake = _FakeElastic(search=search)
    _patch_elastic(monkeypatch, fake)
    result = await doctor.check_alerts_feed_filter(_alerts_settings(settings_kratos, union))
    assert result.status == "PASS"


async def test_alerts_filter_zero_coverage_ignores_a_truncated_class_list(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """A class list the grid cut short cannot prove a class is missing.

    ``sum_other_doc_count`` above zero means the terms aggregation dropped
    buckets, so "the configured filter matches none of X" may only mean "X fell
    off the end of the list". A check that fires on that is a false alarm on a
    healthy grid, which is the failure mode this row is least able to afford.
    """
    search = _FakeAlertFilterSearch(
        {"event.dataset:suricata.alert": 1441, "tags:alert": 1442},
        datasets={
            "event.dataset:suricata.alert": {"suricata.alert": 1441},
            "tags:alert": {"suricata.alert": 1441, "sigma.alert": 1},
        },
        truncated={"event.dataset:suricata.alert"},
    )
    fake = _FakeElastic(search=search)
    _patch_elastic(monkeypatch, fake)
    result = await doctor.check_alerts_feed_filter(
        _alerts_settings(settings_kratos, "event.dataset:suricata.alert")
    )
    assert result.status == "PASS"


async def test_alerts_filter_hint_says_where_the_value_actually_lives(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """The hint names both places the value can live, and which one wins.

    On the deployed instance ``WEBUI_ALERTS_QUERY`` is set in an environment
    file, and the config console writes a database override that is applied over
    the environment at startup. Telling the owner to use the console is only
    true because of that precedence, so the sentence says it: a console save
    takes effect immediately and outranks the file.
    """
    search = _FakeAlertFilterSearch({"tags:alerts": 22, "event.kind:alert": 25})
    fake = _FakeElastic(search=search)
    _patch_elastic(monkeypatch, fake)
    result = await doctor.check_alerts_feed_filter(_alerts_settings(settings_kratos, "tags:alert"))
    assert "WEBUI_ALERTS_QUERY" in result.hint
    assert "Queries" in result.hint
    assert "overrides" in result.hint or "outranks" in result.hint


async def test_doctor_grades_the_filter_the_app_actually_runs(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings, tmp_path: Path
) -> None:
    """``soc-ai doctor`` reads the saved console overrides, not just the env file.

    Measured on the deployed instance: ``ORACLE_MODEL`` is one value in the
    environment file and another in ``config_overrides``, and the running app
    uses the database one. A doctor that grades only the file grades a
    configuration nothing is running, and it would go on reporting the same
    alerts-filter warning after the owner fixed it in the console, which is the
    one place the hint sends them.
    """
    from soc_ai.store.config_overrides import set_override
    from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

    settings = settings_kratos.model_copy(
        update={"soc_ai_data_dir": tmp_path, "webui_alerts_query": "tags:alert"}
    )
    engine = make_engine(settings)
    await run_migrations(engine)
    async with make_sessionmaker(engine)() as db:
        await set_override(
            db, "webui_alerts_query", "tags:alert OR event.kind:alert", updated_by=None
        )
    await engine.dispose()

    applied = await doctor.apply_persisted_overrides(settings)
    assert applied == ["webui_alerts_query"]
    assert settings.webui_alerts_query == "tags:alert OR event.kind:alert"


async def test_doctor_override_read_is_fail_soft_without_a_store(
    settings_kratos: Settings, tmp_path: Path
) -> None:
    """No store yet (a fresh install running the doctor first) is not an error.

    ``check_store`` reports a missing or broken store on its own row; this read
    must never be the thing that takes the doctor down.
    """
    settings = settings_kratos.model_copy(update={"soc_ai_data_dir": tmp_path / "nope"})
    assert await doctor.apply_persisted_overrides(settings) == []
