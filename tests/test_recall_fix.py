"""Deterministic tests for the recall fix (docs/dev/recall-fix-2026-07-02.md).

Cluster-free: they feed synth-shaped ES docs / reports through the surfacing,
materialization, coverage-credit, and evidence-gate layers and assert the decisive
evidence survives and a pivot-grounded escalation is not downgraded.
"""

from __future__ import annotations

from typing import Any

from soc_ai.agent.orchestrator import (
    _credit_prefetch_coverage,
    _derive_rubric_coverage,
    _downgrade_unevidenced_verdict,
    _materialize_prefetch_evidence,
    _pivot_decisive_evidence,
    _verdict_cites_decisive_pivot_value,
    _verdict_grounded_in_pivot,
)
from soc_ai.agent.triage import RubricCoverage, TriageReport
from soc_ai.enrichment.zeek_parser import parse_typed_zeek_fields
from soc_ai.so_client.models import SoAlert
from soc_ai.tools.get_alert_context import EnrichedAlertContext


def _alert() -> SoAlert:
    return SoAlert.from_es_hit(
        {
            "_id": "alert-1",
            "_source": {
                "event.dataset": "suricata.alert",
                "rule.name": "ET HUNTING Possible Cobalt Strike",
                "source.ip": "10.0.0.115",
                "destination.ip": "104.18.42.69",
            },
        }
    )


def _zeek(_id: str, dataset: str, extra: dict[str, Any]) -> SoAlert:
    return SoAlert.from_es_hit({"_id": _id, "_source": {"event.dataset": dataset, **extra}})


# ── Wave 1/2: extraction + aggregation surface the decisive fields ──────────────


def test_extract_zeek_typed_new_protocols() -> None:
    krb = _zeek(
        "k1",
        "zeek.kerberos",
        {"zeek.kerberos.cipher": "rc4-hmac", "zeek.kerberos.service": "MSSQLSvc/db01"},
    )
    smb = _zeek(
        "s1",
        "zeek.smb_files",
        {"zeek.smb_files.action": "SMB::FILE_WRITE", "zeek.smb_files.name": "PSEXESVC.exe"},
    )
    dce = _zeek(
        "d1",
        "zeek.dce_rpc",
        {"zeek.dce_rpc.endpoint": "svcctl", "zeek.dce_rpc.operation": "CreateServiceW"},
    )
    assert krb.zeek_kerberos_cipher == "rc4-hmac"
    assert krb.zeek_kerberos_service == "MSSQLSvc/db01"
    assert smb.zeek_smb_action == "SMB::FILE_WRITE"
    assert smb.zeek_smb_name == "PSEXESVC.exe"
    assert dce.zeek_dce_rpc_endpoint == "svcctl"
    assert dce.zeek_dce_rpc_operation == "CreateServiceW"


def test_extract_and_materialize_ssh_login() -> None:
    ssh = _zeek(
        "ssh1",
        "zeek.ssh",
        {
            "zeek.ssh.auth_success": True,
            "zeek.ssh.auth_attempts": 1,
            "zeek.ssh.client": "OpenSSH_8.9",
        },
    )
    assert ssh.zeek_ssh_auth_success is True
    assert ssh.zeek_ssh_auth_attempts == 1
    bullets = " ".join(_pivot_decisive_evidence(ssh, "ssh1"))
    assert "completed SSH login" in bullets and "auth_success=true" in bullets


def test_exfil_bullet_includes_low_and_slow_duration() -> None:
    conn = _zeek(
        "c1",
        "zeek.conn",
        {
            "zeek.conn.orig_bytes": 4_200_000_000,
            "zeek.conn.resp_bytes": 4_100_000,
            "event.duration": 32400.0,
        },
    )
    bullets = " ".join(_pivot_decisive_evidence(conn, "c1"))
    assert "outbound-dominant transfer" in bullets and "low-and-slow" in bullets


def test_beacon_profile_surfaces_decisive_bullet() -> None:
    # RITA-style beacon summary doc (m1 shape): 95% interval similarity + low byte CV.
    beacon = _zeek(
        "b1",
        "zeek.conn_summary",
        {
            "synth.beacon_profile": {
                "connection_count": 240,
                "mean_interval_seconds": 60.1,
                "interval_similarity": 0.95,
                "orig_bytes_cv": 0.04,
                "resp_bytes_cv": 0.06,
            }
        },
    )
    assert beacon.zeek_beacon_profile is not None
    bullets = " ".join(_pivot_decisive_evidence(beacon, "b1"))
    assert "periodic beacon profile" in bullets
    assert "95% interval similarity" in bullets and "240 connections" in bullets


def test_beacon_profile_ignored_when_irregular() -> None:
    # Human-ish traffic: low similarity, high variance → no beacon bullet.
    beacon = _zeek(
        "b2",
        "zeek.conn_summary",
        {"synth.beacon_profile": {"interval_similarity": 0.20, "orig_bytes_cv": 0.9}},
    )
    assert _pivot_decisive_evidence(beacon, "b2") == []


def test_dns_tunnel_profile_surfaces_decisive_bullet() -> None:
    # DNS-tunnel summary doc (m2 shape): high volume + entropy + TXT-dominant.
    dns = _zeek(
        "d1",
        "zeek.dns_summary",
        {
            "synth.dns_profile": {
                "parent_domain": "update-cdn.click",
                "query_count": 6018,
                "unique_subdomains": 5912,
                "qname_label_entropy_mean": 4.21,
                "qtype_distribution": {"TXT": 4892, "NULL": 1014, "A": 112},
            }
        },
    )
    assert dns.zeek_dns_profile is not None
    bullets = " ".join(_pivot_decisive_evidence(dns, "d1"))
    assert "DNS-tunnel aggregate" in bullets and "update-cdn.click" in bullets
    assert "6018 queries" in bullets and "label entropy 4.21" in bullets


def test_dns_tunnel_profile_ignored_for_ordinary_dns() -> None:
    # Normal resolver traffic: low volume, low entropy, A-record → no tunnel bullet.
    dns = _zeek(
        "d2",
        "zeek.dns_summary",
        {
            "synth.dns_profile": {
                "query_count": 40,
                "qname_label_entropy_mean": 2.1,
                "qtype_distribution": {"A": 38, "AAAA": 2},
            }
        },
    )
    assert _pivot_decisive_evidence(dns, "d2") == []


def test_extract_zeek_typed_previously_unread_tables() -> None:
    dns = _zeek("dn1", "zeek.dns", {"zeek.dns.qtype_name": "TXT"})
    ssl = _zeek("ss1", "zeek.ssl", {"zeek.ssl.established": True})
    assert dns.zeek_dns_qtype == "TXT"
    assert ssl.zeek_ssl_established is True


def test_parse_typed_zeek_surfaces_ja3_pair_and_bytes() -> None:
    ssl = _zeek("s1", "zeek.ssl", {"zeek.ssl.ja3": "a0e9f5", "zeek.ssl.ja3s": "b742b4"})
    conn = _zeek(
        "c1",
        "zeek.conn",
        {"zeek.conn.orig_bytes": 4_200_000_000, "zeek.conn.resp_bytes": 4_100_000},
    )
    f = _zeek(
        "f1",
        "zeek.files",
        {"zeek.files.mime_type": "application/x-dosexec", "zeek.files.sha256": "d" * 64},
    )
    typed = parse_typed_zeek_fields([ssl, conn, f])
    assert typed.ja3_hashes == ["a0e9f5"]
    assert typed.ja3s_hashes == ["b742b4"]
    assert 4_200_000_000 in typed.conn_orig_bytes
    assert "application/x-dosexec" in typed.file_mime_types
    assert "d" * 64 in typed.file_sha256s


def test_parse_typed_zeek_message_fallback_still_works() -> None:
    # A doc whose zeek log is only in message JSON (no typed attrs) still yields SNI.
    p = SoAlert(id="x", event_dataset="zeek.ssl", message='{"server_name": "api.giphy.com"}')
    typed = parse_typed_zeek_fields([p])
    assert typed.sni_servers == ["api.giphy.com"]


# ── Wave 1: materialization makes the decisive field a prominent cited bullet ────


def test_materialize_surfaces_decisive_pivot_bullets() -> None:
    ctx = EnrichedAlertContext(
        alert=_alert(),
        community_id_events=[
            _zeek("s1", "zeek.ssl", {"zeek.ssl.ja3": "a0e9f5", "zeek.ssl.ja3s": "b742b4"}),
            _zeek(
                "k1",
                "zeek.kerberos",
                {"zeek.kerberos.cipher": "rc4-hmac", "zeek.kerberos.service": "MSSQLSvc/db01"},
            ),
        ],
    )
    ev = "\n".join(_materialize_prefetch_evidence(ctx))
    assert "JA3" in ev and "a0e9f5" in ev and "b742b4" in ev
    assert "Kerberos" in ev and "rc4-hmac" in ev and "id k1" in ev


# ── Wave 4: hard evidence gate — pivot-grounded escalation is NOT downgraded ─────


def _pivot_ctx() -> EnrichedAlertContext:
    return EnrichedAlertContext(
        alert=_alert(),
        community_id_events=[
            _zeek("piv-ssl-1", "zeek.ssl", {"zeek.ssl.ja3": "a0e9f5", "zeek.ssl.ja3s": "b742b4"})
        ],
    )


def test_verdict_grounded_in_pivot_by_id() -> None:
    report = TriageReport(
        verdict="true_positive",
        confidence=0.8,
        summary="C2",
        citations=["community_id pivot id piv-ssl-1"],
    )
    assert _verdict_grounded_in_pivot(report, _pivot_ctx()) is True


def test_verdict_grounded_in_pivot_by_decisive_value() -> None:
    report = TriageReport(
        verdict="true_positive",
        confidence=0.8,
        summary="C2",
        citations=["JA3S b742b4 matches a Cobalt Strike team server"],
    )
    assert _verdict_grounded_in_pivot(report, _pivot_ctx()) is True


def test_confidence_floor_raise_requires_decisive_value_not_bare_id() -> None:
    # The floor-raise must NOT fire on a mere pivot-doc id: every alert has
    # correlated pivots, so citing one proves nothing about maliciousness.
    id_only = TriageReport(
        verdict="true_positive",
        confidence=0.8,
        summary="C2",
        citations=["community_id pivot id piv-ssl-1"],
    )
    assert _verdict_cites_decisive_pivot_value(id_only, _pivot_ctx()) is False
    # A cited decisive VALUE (the JA3S) IS a malicious-leaning signal → floor may fire.
    value_cite = TriageReport(
        verdict="true_positive",
        confidence=0.8,
        summary="C2",
        citations=["JA3S b742b4 matches a Cobalt Strike team server"],
    )
    assert _verdict_cites_decisive_pivot_value(value_cite, _pivot_ctx()) is True


def test_verdict_citing_only_alert_is_not_pivot_grounded() -> None:
    report = TriageReport(
        verdict="true_positive",
        confidence=0.8,
        summary="rule name looks bad",
        citations=["alert.rule_name"],
    )
    assert _verdict_grounded_in_pivot(report, _pivot_ctx()) is False


def test_hard_gate_exempts_pivot_grounded_escalation() -> None:
    report = TriageReport(
        verdict="true_positive",
        confidence=0.85,
        summary="CS beacon: JA3 pair on pivot",
        citations=["community_id pivot id piv-ssl-1", "JA3/JA3S pair a0e9f5 / b742b4"],
    )
    audit: dict[str, Any] = {}
    out = _downgrade_unevidenced_verdict(
        report, _pivot_ctx(), None, audit, targeted_messages=None, targeted_tool_called=None
    )
    assert out.verdict == "true_positive"
    assert out.confidence == 0.85
    assert "evidence_gate_downgrade" not in audit
    assert "evidence_gate_pivot_exemption" in audit


def test_hard_gate_still_downgrades_alert_only_rationalization() -> None:
    # QVOD defense preserved: a verdict citing only the alert's own fields, with no
    # tool call and no pivot citation, is still coerced to needs_more_info.
    report = TriageReport(
        verdict="true_positive",
        confidence=0.9,
        summary="rule name looks malicious",
        citations=["alert.rule_name"],
    )
    audit: dict[str, Any] = {}
    out = _downgrade_unevidenced_verdict(
        report, _pivot_ctx(), None, audit, targeted_messages=None, targeted_tool_called=None
    )
    assert out.verdict == "needs_more_info"
    assert "evidence_gate_downgrade" in audit


# ── Wave 3: coverage cap credits prefetch-provided coverage ─────────────────────


def test_credit_prefetch_coverage_from_enriched_context() -> None:
    ctx = EnrichedAlertContext(
        alert=_alert(),
        community_id_events=[_zeek("s1", "zeek.ssl", {"zeek.ssl.server_name": "cdn.example.com"})],
        host_events=[_zeek("h1", "zeek.conn", {})],
        enrichments={},
    )
    ctx.enrichments = {"10.0.0.115": object()}  # type: ignore[dict-item]
    out = RubricCoverage()
    _credit_prefetch_coverage(out, ctx)
    assert out.enrichment_called is True
    assert out.related_alerts_checked is True
    assert out.dns_or_sni_pivoted is True


def test_derive_rubric_coverage_credits_prefetch_without_tool_calls() -> None:
    ctx = EnrichedAlertContext(
        alert=_alert(),
        community_id_events=[_zeek("s1", "zeek.ssl", {"zeek.ssl.ja3": "abc"})],
        host_events=[_zeek("h1", "zeek.conn", {})],
    )
    ctx.enrichments = {"10.0.0.115": object()}  # type: ignore[dict-item]
    cov = _derive_rubric_coverage([], ctx)
    assert cov.enrichment_called is True
    assert cov.related_alerts_checked is True
    assert cov.dns_or_sni_pivoted is True


# ── Wave 6: metric honesty — verdict-only recall + FN breakdown ─────────────────


def _tp_scenario(sid: str, tier: str, floor: float) -> Any:
    import types

    gt = types.SimpleNamespace(
        verdict="true_positive",
        confidence_min=floor,
        required_citation_kinds=[],
        expected_actions=[],
    )
    return types.SimpleNamespace(id=sid, tier=tier, ground_truth=gt)


def test_recall_verdict_only_credits_underconfident_escalation() -> None:
    from soc_ai.eval.synth_score import SynthRow, score_synth_stratum

    scenarios = [
        _tp_scenario("a", "easy", 0.70),  # correct @ floor → strict TP
        _tp_scenario("b", "easy", 0.75),  # correct verdict @ 0.60 (below floor) → e2/e3-style
        _tp_scenario("c", "medium", 0.70),  # no row → errored / infra loss
    ]
    rows = [
        SynthRow("a", "true_positive", 0.80, []),
        SynthRow("b", "true_positive", 0.60, []),
    ]
    s = score_synth_stratum(rows, scenarios=scenarios)
    # Strict recall counts only the high-confidence TP (1/3).
    assert abs(s.escalation_recall - 1 / 3) < 1e-9
    # Verdict-only recall credits both correct escalations (2/3).
    assert abs(s.escalation_recall_verdict_only - 2 / 3) < 1e-9
    # FN split isolates the calibration miss from the infra loss.
    assert s.false_negative_breakdown == {"missed": 0, "low_confidence": 1, "errored": 1}


def test_recall_verdict_only_counts_wrong_verdict_as_missed() -> None:
    from soc_ai.eval.synth_score import SynthRow, score_synth_stratum

    scenarios = [_tp_scenario("a", "hard", 0.70)]
    rows = [SynthRow("a", "false_positive", 0.9, [])]  # genuine miss (wrong verdict)
    s = score_synth_stratum(rows, scenarios=scenarios)
    assert s.escalation_recall == 0.0
    assert s.escalation_recall_verdict_only == 0.0
    assert s.false_negative_breakdown["missed"] == 1
