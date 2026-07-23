"""Tests for :mod:`soc_ai.audit`."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.audit.chain import GENESIS_PREV_HASH, compute_hash, verify_chain
from soc_ai.audit.logger import AuditLogger, AuditWriteError
from soc_ai.audit.redact import redact_text, redact_value
from soc_ai.audit.schemas import AuditEvent
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient


class _CapturingES:
    """Minimal in-memory ES double for hash-chain tests.

    Captures every indexed body (so we can recover the stored records) and
    serves them back via ``search`` so a fresh :class:`AuditLogger` can recover
    the chain head on restart. ``index`` may be told to raise to simulate an ES
    outage.
    """

    def __init__(self, *, fail: bool = False) -> None:
        self.docs: list[dict[str, Any]] = []
        self.fail = fail
        self.indices = AsyncMock()  # put_index_template etc. are no-ops

    async def index(self, *, index: str, body: dict[str, Any]) -> None:
        if self.fail:
            raise RuntimeError("ES down")
        self.docs.append(body)

    async def search(self, *, index: str, body: dict[str, Any]) -> dict[str, Any]:
        chained = [d for d in self.docs if d.get("seq") is not None]
        if not chained:
            return {"hits": {"hits": []}}
        top = max(chained, key=lambda d: d["seq"])
        return {"hits": {"hits": [{"_source": top}]}}


def _logger_with(es: _CapturingES, settings: Settings) -> AuditLogger:
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=es):
        elastic = ElasticClient(settings)
    return AuditLogger(settings, elastic)


# =====================================================================
# Redactor
# =====================================================================


def test_redact_text_aws_access_key() -> None:
    out, modified = redact_text("aws AKIAIOSFODNN7EXAMPLE in env")
    assert "[REDACTED:aws_access_key]" in out
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert modified


def test_redact_text_github_token() -> None:
    out, modified = redact_text("token: ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    assert "[REDACTED:github_token]" in out
    assert modified


def test_redact_text_jwt() -> None:
    jwt = (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    out, modified = redact_text(f"Authorization: Bearer {jwt}")
    assert "[REDACTED:jwt]" in out
    assert modified


def test_redact_text_email() -> None:
    out, modified = redact_text("contact alice@example.com please")
    assert "[REDACTED:email]" in out
    assert modified


def test_redact_text_no_match_returns_unchanged() -> None:
    out, modified = redact_text("nothing sensitive here")
    assert out == "nothing sensitive here"
    assert not modified


def test_redact_text_scai_api_token() -> None:
    out, modified = redact_text("auth via scai_abcdefghijklmnopqrstuvwxyz0123456789")
    assert "[REDACTED:scai_token]" in out
    assert "scai_abcdefghijklmnopqrstuvwxyz0123456789" not in out
    assert modified


def test_redact_text_bearer_authorization() -> None:
    out, modified = redact_text("Authorization: Bearer abc123.def-456_token")
    assert "[REDACTED:bearer]" in out
    assert "abc123.def-456_token" not in out
    assert modified


def test_redact_text_session_token_header() -> None:
    out, modified = redact_text("X-Session-Token: s3cr3t-session-value-xyz")
    assert "[REDACTED:session_token]" in out
    assert "s3cr3t-session-value-xyz" not in out
    assert modified


def test_redact_text_key_value_secret() -> None:
    for line in (
        "password=hunter2",
        "api_key: AKfancyvalue99",
        "secret = topsecretvalue",
        "pwd:letmein",
    ):
        out, modified = redact_text(line)
        assert "[REDACTED:secret]" in out, line
        assert modified, line


def test_redact_text_multiword_secret_fully_masked() -> None:
    """A secret value with spaces is redacted in FULL, not just its first token —
    else the bulk of a passphrase leaks verbatim into the shared ES cluster."""
    out, modified = redact_text("password = correct horse battery staple")
    assert modified
    assert "[REDACTED:secret]" in out
    assert "horse" not in out
    assert "battery" not in out
    assert "staple" not in out


def test_redact_text_multiword_secret_stops_at_delimiter() -> None:
    """The value capture stops at a natural field delimiter so a following,
    non-secret field isn't swallowed into the redaction."""
    out, _ = redact_text("password = my long pass, user=bob")
    assert "[REDACTED:secret]" in out
    assert "long" not in out
    assert "user=bob" in out


def test_redact_value_dict_recursive() -> None:
    payload = {
        "args": {"comment": "please contact alice@example.com"},
        "ids": ["abc", "def"],
    }
    out, modified = redact_value(payload)
    assert modified
    assert "[REDACTED:email]" in out["args"]["comment"]
    assert out["ids"] == ["abc", "def"]


def test_redact_value_list_of_strings() -> None:
    out, modified = redact_value(["plain", "alice@example.com", "bob"])
    assert modified
    assert "[REDACTED:email]" in out[1]


def test_redact_value_non_string_passthrough() -> None:
    out, modified = redact_value(42)
    assert out == 42
    assert not modified


# =====================================================================
# AuditEvent schema
# =====================================================================


def test_audit_event_defaults() -> None:
    ev = AuditEvent(session_id="s1", kind="tool_call", payload={"x": 1})
    assert ev.user == "unknown"
    assert ev.redacted is False
    assert isinstance(ev.timestamp, datetime)


# =====================================================================
# AuditLogger
# =====================================================================


@pytest.mark.asyncio
async def test_audit_logger_writes_to_dated_index(settings_kratos: Settings) -> None:
    fake_es = AsyncMock()
    fake_es.index = AsyncMock()
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        elastic = ElasticClient(settings_kratos)

    logger = AuditLogger(settings_kratos, elastic)
    ev = AuditEvent(
        session_id="s1",
        kind="tool_call",
        payload={"tool": "ack_alert"},
        timestamp=datetime(2026, 5, 7, 12, 0, 0, tzinfo=UTC),
    )
    await logger.log(ev)

    fake_es.index.assert_awaited_once()
    call = fake_es.index.call_args.kwargs
    assert call["index"] == "soc-ai-audit-2026.05.07"
    assert call["body"]["session_id"] == "s1"


@pytest.mark.asyncio
async def test_audit_logger_redacts_when_enabled(
    settings_with_misp: Settings,
) -> None:
    """AUDIT_REDACT=true scrubs payload + reasoning_trace, sets redacted=True."""
    settings_redact = settings_with_misp.model_copy(update={"audit_redact": True})

    fake_es = AsyncMock()
    fake_es.index = AsyncMock()
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        elastic = ElasticClient(settings_redact)

    logger = AuditLogger(settings_redact, elastic)
    ev = AuditEvent(
        session_id="s1",
        kind="llm_response",
        payload={"content": "ping alice@example.com"},
        reasoning_trace="thinking about bob@example.com",
    )
    await logger.log(ev)

    body = fake_es.index.call_args.kwargs["body"]
    assert "[REDACTED:email]" in body["payload"]["content"]
    assert "[REDACTED:email]" in body["reasoning_trace"]
    assert body["redacted"] is True


@pytest.mark.asyncio
async def test_audit_logger_swallows_es_failure(settings_kratos: Settings) -> None:
    """An ES failure must NOT crash the investigation - just log and drop."""
    fake_es = AsyncMock()
    fake_es.index = AsyncMock(side_effect=RuntimeError("ES down"))
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        elastic = ElasticClient(settings_kratos)

    logger = AuditLogger(settings_kratos, elastic)
    ev = AuditEvent(session_id="s1", kind="tool_call", payload={})
    # Must not raise
    await logger.log(ev)


@pytest.mark.asyncio
async def test_audit_logger_installs_flattened_template_once(settings_kratos: Settings) -> None:
    """The payload.result object-vs-scalar mapping conflict is fixed by a
    composable template mapping `payload` as `flattened`, installed once."""
    fake_es = AsyncMock()
    fake_es.index = AsyncMock()
    fake_es.indices.put_index_template = AsyncMock()
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        elastic = ElasticClient(settings_kratos)
    logger = AuditLogger(settings_kratos, elastic)

    # Two events whose payload.result differs in type (object then scalar) — the
    # exact conflict the template resolves.
    await logger.log(AuditEvent(session_id="s", kind="tool_call", payload={"result": {"x": 1}}))
    await logger.log(AuditEvent(session_id="s", kind="tool_call", payload={"result": "ok"}))

    fake_es.indices.put_index_template.assert_awaited_once()  # once, not per-log
    kw = fake_es.indices.put_index_template.call_args.kwargs
    assert kw["name"] == "soc-ai-audit-template"
    assert kw["index_patterns"] == ["soc-ai-audit-*"]
    assert kw["template"]["mappings"]["properties"]["payload"]["type"] == "flattened"
    assert fake_es.index.await_count == 2  # both events still indexed


@pytest.mark.asyncio
async def test_audit_logger_template_failure_does_not_break_log(settings_kratos: Settings) -> None:
    """A template-install failure (e.g. no privilege) must not stop the write."""
    fake_es = AsyncMock()
    fake_es.index = AsyncMock()
    fake_es.indices.put_index_template = AsyncMock(side_effect=RuntimeError("forbidden"))
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        elastic = ElasticClient(settings_kratos)
    logger = AuditLogger(settings_kratos, elastic)

    await logger.log(AuditEvent(session_id="s", kind="tool_call", payload={}))
    fake_es.index.assert_awaited_once()  # write still happened despite template failure


@pytest.mark.asyncio
async def test_audit_logger_log_kind_helper(settings_kratos: Settings) -> None:
    fake_es = AsyncMock()
    fake_es.index = AsyncMock()
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        elastic = ElasticClient(settings_kratos)

    logger = AuditLogger(settings_kratos, elastic)
    await logger.log_kind(
        "s1",
        "llm_request",
        {"prompt": "x"},
        model_alias="heavy",
        reasoning_mode="full",
    )

    body = fake_es.index.call_args.kwargs["body"]
    assert body["kind"] == "llm_request"
    assert body["model_alias"] == "heavy"
    assert body["reasoning_mode"] == "full"


# =====================================================================
# AuditKind completeness — regression for live journal errors
# =====================================================================


def test_citation_validation_kind_is_valid() -> None:
    """Regression: orchestrator emits citation_validation audit events.

    Live journal error 2026-06-12: pydantic rejected input_value='citation_validation'.
    """
    ev = AuditEvent(kind="citation_validation", session_id="s", payload={})
    assert ev.kind == "citation_validation"


def test_all_orchestrator_kinds_are_valid() -> None:
    """Every kind the orchestrator passes to _ev() must be a valid AuditKind."""
    orchestrator_kinds = [
        # core flow
        "session_start",
        "alert_context",
        "enriched_alert_context",
        "classification",
        "triage_report",
        "done",
        "error",
        # citation validators
        "citation_validation",
        "citation_cap",
        "template_ceiling",
        "verdict_floor_rewrite",
        # coverage / rubric
        "coverage_cap",
        "rubric_derivation",
        # fast-path
        "fast_path_escalation",
        "fast_path_evidence_guard",
        "fast_path_verdict_cap",
        # icmp / targeted
        "icmp_solicited_downgrade",
        "targeted_dispatch",
        "targeted_tool_result",
        # decision helpers
        "decision_template_match",
        "recommended_actions_blocked",
        # retask
        "retask",
        "retask_skipped_no_closeable_gap",
        # tool / approval
        "tool_call",
        "tool_result",
        "approval_required",
        # transcripts / usage
        "investigation_transcript",
        "usage",
    ]
    for kind in orchestrator_kinds:
        ev = AuditEvent(kind=kind, session_id="s", payload={})  # type: ignore[arg-type]
        assert ev.kind == kind, f"AuditKind missing: {kind!r}"


# =====================================================================
# Tamper-evident hash chain
# =====================================================================


def test_audit_event_chain_fields_default_none() -> None:
    """Chain fields are None on a freshly-built event (backward compatible)."""
    ev = AuditEvent(session_id="s", kind="tool_call", payload={})
    assert ev.seq is None
    assert ev.prev_hash is None
    assert ev.hash is None


def test_verify_chain_ignores_legacy_records() -> None:
    """Records that predate the chain (no seq/hash) verify OK (treated as empty)."""
    legacy = [
        {"session_id": "s", "kind": "tool_call", "payload": {"a": 1}},
        {"session_id": "s", "kind": "tool_result", "payload": {"b": 2}},
    ]
    ok, broken = verify_chain(legacy)
    assert ok is True
    assert broken is None


@pytest.mark.asyncio
async def test_chain_of_n_events_verifies_ok(settings_kratos: Settings) -> None:
    """A chain of N successfully-written events verifies OK and is well-linked."""
    es = _CapturingES()
    logger = _logger_with(es, settings_kratos)

    for i in range(5):
        await logger.log_kind("s", "tool_call", {"i": i})

    assert len(es.docs) == 5
    # seq is 0..4, first prev_hash is genesis, each links to the prior hash.
    assert [d["seq"] for d in es.docs] == [0, 1, 2, 3, 4]
    assert es.docs[0]["prev_hash"] == GENESIS_PREV_HASH
    for prev, cur in zip(es.docs, es.docs[1:], strict=False):
        assert cur["prev_hash"] == prev["hash"]

    ok, broken = verify_chain(es.docs)
    assert ok is True
    assert broken is None


@pytest.mark.asyncio
async def test_tampering_middle_record_content_breaks_chain(
    settings_kratos: Settings,
) -> None:
    """Editing a middle record's content makes its recomputed hash mismatch."""
    es = _CapturingES()
    logger = _logger_with(es, settings_kratos)
    for i in range(5):
        await logger.log_kind("s", "tool_call", {"i": i})

    # Tamper: rewrite the payload of the record at seq=2 (leave its stored hash).
    es.docs[2]["payload"] = {"i": "ATTACKER-CHANGED"}

    ok, broken = verify_chain(es.docs)
    assert ok is False
    assert broken == 2


@pytest.mark.asyncio
async def test_deleting_record_breaks_chain(settings_kratos: Settings) -> None:
    """Deleting a record leaves a seq gap that verify_chain detects."""
    es = _CapturingES()
    logger = _logger_with(es, settings_kratos)
    for i in range(5):
        await logger.log_kind("s", "tool_call", {"i": i})

    del es.docs[2]  # drop seq=2; now 0,1,3,4 — gap at 2

    ok, broken = verify_chain(es.docs)
    assert ok is False
    # The record that should have been seq=2 is now seq=3 → first mismatch at 3.
    assert broken == 3


@pytest.mark.asyncio
async def test_chain_head_recovers_across_restart(settings_kratos: Settings) -> None:
    """A new logger reading the same ES continues the chain (no seq reset)."""
    es = _CapturingES()
    logger1 = _logger_with(es, settings_kratos)
    for i in range(3):
        await logger1.log_kind("s", "tool_call", {"i": i})
    assert [d["seq"] for d in es.docs] == [0, 1, 2]

    # Simulated restart: a fresh logger over the same ES recovers the head.
    logger2 = _logger_with(es, settings_kratos)
    await logger2.log_kind("s", "tool_call", {"i": 3})

    assert [d["seq"] for d in es.docs] == [0, 1, 2, 3]
    assert es.docs[3]["prev_hash"] == es.docs[2]["hash"]
    ok, broken = verify_chain(es.docs)
    assert ok is True
    assert broken is None


@pytest.mark.asyncio
async def test_windowed_verify_skips_genesis_boundary(settings_kratos: Settings) -> None:
    """A mid-stream window (what ``days=N`` returns on an old deployment) is not a
    tamper. ``expect_genesis=False`` leaves the first record's boundary linkage
    UNVERIFIED instead of forcing the genesis prev_hash; the default full-scan mode
    still flags a missing head (seq>0 first record with a non-genesis prev_hash)."""
    es = _CapturingES()
    logger = _logger_with(es, settings_kratos)
    for i in range(10):
        await logger.log_kind("s", "tool_call", {"i": i})

    window = es.docs[6:]  # seqs 6..9 — exactly what a days= filter hands back

    # Default (full-scan) mode forces the genesis check → false 'tamper' at seq 6.
    ok_full, broken_full = verify_chain(window)
    assert ok_full is False
    assert broken_full == 6

    # Windowed mode: boundary is UNVERIFIED, not tampered → intact.
    ok_win, broken_win = verify_chain(window, expect_genesis=False)
    assert ok_win is True
    assert broken_win is None


def test_compute_hash_is_order_independent() -> None:
    """Canonicalisation makes the digest independent of dict insertion order."""
    a = {"seq": 1, "payload": {"x": 1, "y": 2}, "kind": "tool_call"}
    b = {"kind": "tool_call", "payload": {"y": 2, "x": 1}, "seq": 1}
    assert compute_hash(a, "ff" * 32) == compute_hash(b, "ff" * 32)


# =====================================================================
# Fail-closed for mutating writes
# =====================================================================


@pytest.mark.asyncio
async def test_mutating_write_fail_closed_aborts(settings_kratos: Settings) -> None:
    """audit_fail_closed=True: a mutating audit write that fails raises."""
    settings = settings_kratos.model_copy(update={"audit_fail_closed": True})
    es = _CapturingES(fail=True)
    logger = _logger_with(es, settings)

    with pytest.raises(AuditWriteError):
        await logger.log_kind("s", "tool_call", {"tool": "ack_alert"}, mutating=True)


@pytest.mark.asyncio
async def test_mutating_write_fail_open_when_setting_off(
    settings_kratos: Settings,
) -> None:
    """audit_fail_closed=False: a mutating audit failure is swallowed (fail-open)."""
    settings = settings_kratos.model_copy(update={"audit_fail_closed": False})
    es = _CapturingES(fail=True)
    logger = _logger_with(es, settings)

    # Must NOT raise.
    await logger.log_kind("s", "tool_call", {"tool": "ack_alert"}, mutating=True)


@pytest.mark.asyncio
async def test_read_write_stays_fail_open_even_with_fail_closed(
    settings_kratos: Settings,
) -> None:
    """A non-mutating (read/triage) audit failure never raises, even fail-closed."""
    settings = settings_kratos.model_copy(update={"audit_fail_closed": True})
    es = _CapturingES(fail=True)
    logger = _logger_with(es, settings)

    # mutating defaults to False — must NOT raise even though audit_fail_closed.
    await logger.log_kind("s", "alert_context", {"x": 1})


@pytest.mark.asyncio
async def test_fail_closed_does_not_advance_chain_head(settings_kratos: Settings) -> None:
    """A failed mutating write must not consume a seq — the chain stays unbroken
    when ES recovers."""
    settings = settings_kratos.model_copy(update={"audit_fail_closed": True})
    es = _CapturingES()
    logger = _logger_with(es, settings)

    await logger.log_kind("s", "tool_call", {"i": 0})  # seq 0 OK
    es.fail = True
    with pytest.raises(AuditWriteError):
        await logger.log_kind("s", "tool_call", {"i": 1}, mutating=True)  # fails
    es.fail = False
    await logger.log_kind("s", "tool_call", {"i": 2})  # should be seq 1, not 2

    assert [d["seq"] for d in es.docs] == [0, 1]
    ok, broken = verify_chain(es.docs)
    assert ok is True
    assert broken is None


def test_auto_ack_is_a_valid_audit_kind() -> None:
    """Regression: ``maybe_auto_ack_fp`` records the unattended ack as an audit
    event with ``kind="auto_ack"`` and the WebUI reads it back to badge an alert
    as auto-acked. When ``"auto_ack"`` was missing from the ``AuditKind`` Literal,
    every auto-ack failed audit validation (silently caught) so no record ever
    landed and the badge never showed. Constructing the event must not raise.
    """
    ev = AuditEvent(
        session_id="auto-ack:abc",
        user="auto-ack",
        kind="auto_ack",
        payload={"es_id": "abc", "success": True},
    )
    assert ev.kind == "auto_ack"
