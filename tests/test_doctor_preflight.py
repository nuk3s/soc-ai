"""Unit tests for the onboarding preflight rows added to the doctor."""

from __future__ import annotations

import socket
import ssl
import threading
from datetime import UTC, datetime
from typing import Any

import pytest
from elastic_transport import ObjectApiResponse
from soc_ai import doctor
from soc_ai.config import Settings
from soc_ai.so_client.elastic import EsSearchResult, GridPartialResultsError


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
    assert result.hint.startswith("Fix Elasticsearch connectivity first")
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
