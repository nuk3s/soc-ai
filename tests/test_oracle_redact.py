"""Tests for :mod:`soc_ai.oracle.redact` — field-aware learning redacter.

Covers:
- Bare hostname in ``host.name`` / ``host_name`` → tokenised as HOST_n.
- Bare username in ``user.name`` → tokenised as USER_n.
- Learned bare host propagated to ``message`` free-text (Pass 2).
- Public ``destination.ip`` passes; private ``source.ip`` tokenised.
- Public ``dns.question.name`` passes; internal domain (suffix) tokenised.
- ``rule.name`` / ``rule_name`` (static ET rule) → NOT treated as host.
- ``unsafe_residue`` with ``known_values`` flags surviving bare names.
- Client: bare hostname in ``host.name`` + ``message`` → HOST_n in payload.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import SecretStr
from soc_ai.agent.triage import TriageReport
from soc_ai.config import Settings
from soc_ai.oracle.client import OracleResult, adjudicate
from soc_ai.oracle.redact import Mapping, sanitize_case
from soc_ai.oracle.sanitize import unsafe_residue

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mapping() -> Mapping:
    return Mapping()


def _make_settings(**kwargs: Any) -> Settings:
    base: dict[str, Any] = {
        "so_host": "https://so.example.com",
        "so_username": "analyst",
        "so_password": SecretStr("password123"),
        "so_verify_ssl": False,
        "es_hosts": ["https://so.example.com:9200"],
        "litellm_base_url": "http://localhost:4000",
        "oracle_enabled": True,
        "oracle_model": "claude-sonnet-4-6",
        "oracle_timeout_s": 30.0,
    }
    base.update(kwargs)
    return Settings(**base)


def _make_ctx(settings: Settings) -> Any:
    ctx = MagicMock()
    ctx.settings = settings
    return ctx


def _stub_report(verdict: str = "false_positive", confidence: float = 0.85) -> TriageReport:
    return TriageReport(
        verdict=verdict,  # type: ignore[arg-type]
        confidence=confidence,
        summary="Test summary.",
        citations=["alert.severity_label"],
        recommended_actions=[],
    )


# ---------------------------------------------------------------------------
# 1. Bare hostname in host.name / host_name → tokenised as HOST_n
# ---------------------------------------------------------------------------


class TestBareHostField:
    def test_host_name_dotted_flat(self) -> None:
        """Flat ``host_name`` field → tokenised unconditionally."""
        m = _mapping()
        case = {"host_name": "FINANCE-PC"}
        out = sanitize_case(case, m)
        assert "FINANCE-PC" not in json.dumps(out)
        assert "HOST_" in json.dumps(out)
        assert m.counters.get("HOST", 0) >= 1

    def test_host_name_nested(self) -> None:
        """Nested ``host.name`` path → tokenised unconditionally."""
        m = _mapping()
        case = {"host": {"name": "FINANCE-PC"}}
        out = sanitize_case(case, m)
        assert "FINANCE-PC" not in json.dumps(out)
        assert "HOST_" in json.dumps(out)

    def test_hostname_flat(self) -> None:
        """Flat ``hostname`` key → tokenised."""
        m = _mapping()
        case = {"hostname": "WORKSTATION-7"}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "WORKSTATION-7" not in text
        assert "HOST_" in text

    def test_agent_name_nested(self) -> None:
        """``agent.name`` → HOST."""
        m = _mapping()
        case = {"agent": {"name": "endpoint-agent-01"}}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "endpoint-agent-01" not in text
        assert "HOST_" in text

    def test_observer_name_flat(self) -> None:
        """``observer_name`` → HOST."""
        m = _mapping()
        case = {"observer_name": "IDS-SENSOR-01"}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "IDS-SENSOR-01" not in text
        assert "HOST_" in text

    def test_beat_hostname(self) -> None:
        """``beat.hostname`` → HOST."""
        m = _mapping()
        case = {"beat": {"hostname": "filebeat-collector"}}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "filebeat-collector" not in text
        assert "HOST_" in text

    def test_related_hosts_list(self) -> None:
        """``related.hosts`` list → each element tokenised as HOST."""
        m = _mapping()
        case = {"related": {"hosts": ["FINANCE-PC", "DC01", "WORKSTATION-7"]}}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "FINANCE-PC" not in text
        assert "DC01" not in text
        assert "WORKSTATION-7" not in text
        assert m.counters.get("HOST", 0) >= 3

    def test_name_under_host_parent(self) -> None:
        """Bare ``name`` under parent key ``host`` → HOST."""
        m = _mapping()
        # Simulates a nested structure where parent key is "host" but the child
        # dict is at a different nesting than "host.name".
        case = {"host": {"name": "MY-SERVER"}}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "MY-SERVER" not in text
        assert "HOST_" in text


# ---------------------------------------------------------------------------
# 2. Bare username in user.name → tokenised as USER_n
# ---------------------------------------------------------------------------


class TestBareUserField:
    def test_user_name_flat(self) -> None:
        """Flat ``user_name`` → USER_n."""
        m = _mapping()
        case = {"user_name": "jsmith"}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "jsmith" not in text
        assert "USER_" in text

    def test_user_name_nested(self) -> None:
        """Nested ``user.name`` → USER_n."""
        m = _mapping()
        case = {"user": {"name": "jsmith"}}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "jsmith" not in text
        assert "USER_" in text

    def test_username_flat(self) -> None:
        """Flat ``username`` → USER_n."""
        m = _mapping()
        case = {"username": "alice"}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "alice" not in text
        assert "USER_" in text

    def test_source_user_name(self) -> None:
        """``source.user.name`` → USER_n."""
        m = _mapping()
        case = {"source": {"user": {"name": "bob"}}}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "bob" not in text
        assert "USER_" in text

    def test_destination_user_name(self) -> None:
        """``destination.user.name`` → USER_n."""
        m = _mapping()
        case = {"destination": {"user": {"name": "carol"}}}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "carol" not in text
        assert "USER_" in text

    def test_related_user_flat(self) -> None:
        """Flat ``related.user`` → USER_n."""
        m = _mapping()
        case = {"related": {"user": "dave"}}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "dave" not in text
        assert "USER_" in text

    def test_name_under_user_parent(self) -> None:
        """Bare ``name`` under parent key ``user`` → USER."""
        m = _mapping()
        case = {"user": {"name": "eve"}}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "eve" not in text
        assert "USER_" in text


# ---------------------------------------------------------------------------
# 3. Learned bare host propagates into free-text ``message`` field (Pass 2)
# ---------------------------------------------------------------------------


class TestLearnedValuePropagation:
    def test_bare_host_in_host_name_also_redacted_in_message(self) -> None:
        """FINANCE-PC learned from host.name must be redacted in message too."""
        m = _mapping()
        case = {
            "host_name": "FINANCE-PC",
            "message": "Alert: FINANCE-PC initiated outbound connection to 8.8.8.8",
        }
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "FINANCE-PC" not in text, "bare hostname must be removed from message"
        assert "HOST_" in text
        # The public IP must remain.
        assert "8.8.8.8" in text

    def test_bare_user_in_user_name_also_redacted_in_message(self) -> None:
        """jsmith learned from user.name must be redacted in message too."""
        m = _mapping()
        case = {
            "user": {"name": "jsmith"},
            "message": "User jsmith logged in from 192.168.1.50",
        }
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "jsmith" not in text, "bare username must be removed from message"
        assert "USER_" in text
        # The private IP should also be redacted by shape rules.
        assert "192.168.1.50" not in text

    def test_multiple_fields_one_host_consistent_label(self) -> None:
        """Same host in host.name and message → identical HOST_n label."""
        m = _mapping()
        case = {
            "host_name": "FINANCE-PC",
            "message": "FINANCE-PC connected",
        }
        out = sanitize_case(case, m)
        # Only one HOST allocation should exist.
        assert m.counters.get("HOST", 0) == 1
        host_label = m.forward.get("FINANCE-PC") or m.forward.get("finance-pc")
        assert host_label is not None
        text = json.dumps(out)
        assert host_label in text


# ---------------------------------------------------------------------------
# 4. IP fields — private tokenised; public passes
# ---------------------------------------------------------------------------


class TestIPFields:
    def test_private_source_ip_tokenised(self) -> None:
        """``source.ip`` = 10.0.0.5 → tokenised."""
        m = _mapping()
        case = {"source": {"ip": "10.0.0.5"}}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "10.0.0.5" not in text
        assert "IP_" in text

    def test_private_source_ip_flat(self) -> None:
        """Flat ``source_ip`` = 10.0.0.5 → tokenised."""
        m = _mapping()
        case = {"source_ip": "10.0.0.5"}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "10.0.0.5" not in text
        assert "IP_" in text

    def test_public_destination_ip_passes(self) -> None:
        """``destination.ip`` = 8.8.8.8 → NOT tokenised (public)."""
        m = _mapping()
        case = {"destination": {"ip": "8.8.8.8"}}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "8.8.8.8" in text
        assert m.counters.get("IP", 0) == 0

    def test_dest_ip_flat_private(self) -> None:
        """Flat ``destination_ip`` = 192.168.1.5 → tokenised."""
        m = _mapping()
        case = {"destination_ip": "192.168.1.5"}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "192.168.1.5" not in text

    def test_dest_ip_flat_private_dst_variant(self) -> None:
        """Flat ``dst_ip`` = 10.1.2.3 → tokenised."""
        m = _mapping()
        case = {"dst_ip": "10.1.2.3"}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "10.1.2.3" not in text

    def test_zeek_id_orig_h(self) -> None:
        """Zeek ``id.orig_h`` = 172.16.0.1 → tokenised."""
        m = _mapping()
        case = {"id": {"orig_h": "172.16.0.1"}}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "172.16.0.1" not in text

    def test_zeek_id_resp_h_public(self) -> None:
        """Zeek ``id.resp_h`` = 1.2.3.4 → passes (public)."""
        m = _mapping()
        case = {"id": {"resp_h": "1.2.3.4"}}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "1.2.3.4" in text

    def test_community_id_not_tokenised(self) -> None:
        """``network.community_id`` (a hash string) → untouched."""
        m = _mapping()
        cid = "1:AbCdEfGhIjKlMnOp=="
        case = {"network": {"community_id": cid}}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert cid in text


# ---------------------------------------------------------------------------
# 5. DOMAIN fields — internal suffix tokenised; public passes
# ---------------------------------------------------------------------------


class TestDomainFields:
    def test_internal_dns_question_name_tokenised(self) -> None:
        """``dns.question.name`` ending in .corp → tokenised as HOST_n."""
        m = _mapping()
        case = {"dns": {"question": {"name": "dc01.corp"}}}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "dc01.corp" not in text
        assert "HOST_" in text

    def test_public_dns_question_name_passes(self) -> None:
        """``dns.question.name`` = evil.com → NOT tokenised (public domain)."""
        m = _mapping()
        case = {"dns": {"question": {"name": "evil.com"}}}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "evil.com" in text
        assert m.counters.get("HOST", 0) == 0

    def test_internal_domain_field(self) -> None:
        """Flat ``domain`` field ending in .internal → tokenised."""
        m = _mapping()
        case = {"domain": "ad.internal"}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "ad.internal" not in text

    def test_host_domain_internal(self) -> None:
        """``host.domain`` ending in .lan → tokenised."""
        m = _mapping()
        case = {"host": {"domain": "corpnet.lan"}}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "corpnet.lan" not in text


# ---------------------------------------------------------------------------
# 6. rule.name / rule_name → PASSES (static ET rule string, not a host)
# ---------------------------------------------------------------------------


class TestRuleNamePasses:
    def test_rule_name_nested_not_tokenised(self) -> None:
        """``rule.name`` = 'ET MALWARE BPFDoor' → not treated as host."""
        m = _mapping()
        rule = "ET MALWARE BPFDoor Beacon"
        case = {"rule": {"name": rule}}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert rule in text, "rule.name must pass through verbatim"
        assert m.counters.get("HOST", 0) == 0

    def test_rule_name_flat_not_tokenised(self) -> None:
        """Flat ``rule_name`` → not treated as host."""
        m = _mapping()
        rule = "GPL ATTACK_RESPONSE id check returned root"
        case = {"rule_name": rule}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert rule in text
        assert m.counters.get("HOST", 0) == 0

    def test_name_under_rule_parent_not_tokenised(self) -> None:
        """Bare ``name`` under ``rule`` parent → NOT a HOST (rule names are static)."""
        m = _mapping()
        rule = "ET.INFO.Possible.CnC"
        case = {"rule": {"name": rule, "uuid": "abc-123"}}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert rule in text
        # uuid should also pass through
        assert "abc-123" in text
        assert m.counters.get("HOST", 0) == 0


# ---------------------------------------------------------------------------
# 7. unsafe_residue with known_values
# ---------------------------------------------------------------------------


class TestResidueKnownValues:
    def test_known_value_in_text_flagged(self) -> None:
        """A learned real value still present in text → flagged as residue."""
        leaks = unsafe_residue(
            "Outbound from FINANCE-PC to evil.com",
            known_values=("FINANCE-PC",),
        )
        assert any("FINANCE-PC" in leak for leak in leaks), (
            f"Expected 'FINANCE-PC' in residue; got: {leaks}"
        )

    def test_known_value_absent_from_text_no_flag(self) -> None:
        """A learned value not present in text → no residue."""
        leaks = unsafe_residue(
            "Outbound from HOST_01 to evil.com",
            known_values=("FINANCE-PC",),
        )
        assert not any("FINANCE-PC" in leak for leak in leaks)

    def test_clean_string_empty_residue(self) -> None:
        """Fully sanitized text → empty residue list even with known_values."""
        leaks = unsafe_residue(
            "Outbound from HOST_01 to evil.com via IP_02",
            known_values=("FINANCE-PC", "jsmith"),
        )
        assert leaks == []

    def test_opaque_label_in_known_values_not_flagged(self) -> None:
        """Opaque labels (HOST_01 etc.) in known_values are skipped."""
        leaks = unsafe_residue(
            "evidence: HOST_01 reached evil.com",
            known_values=("HOST_01",),
        )
        assert leaks == []

    def test_known_value_word_boundary_respected(self) -> None:
        """'jsmith' in known_values must not fire on 'jsmith_backup'."""
        leaks = unsafe_residue(
            "user jsmith_backup logged in",
            known_values=("jsmith",),
        )
        assert not any("jsmith" in leak for leak in leaks)

    def test_known_value_in_allowlist_not_flagged(self) -> None:
        """A known value that is also allowlisted must not be flagged."""
        leaks = unsafe_residue(
            "host FINANCE-PC is allowlisted",
            known_values=("FINANCE-PC",),
            allowlist=("FINANCE-PC",),
        )
        assert not any("FINANCE-PC" in leak for leak in leaks)

    def test_multiple_known_values_multiple_flags(self) -> None:
        """Multiple surviving known values → multiple residue items."""
        leaks = unsafe_residue(
            "FINANCE-PC and jsmith were found",
            known_values=("FINANCE-PC", "jsmith"),
        )
        leaked = " ".join(leaks)
        assert "FINANCE-PC" in leaked
        assert "jsmith" in leaked

    def test_known_value_case_insensitive(self) -> None:
        """Known value check is case-insensitive (word-boundary, IGNORECASE)."""
        leaks = unsafe_residue(
            "alert from finance-pc to evil.com",
            known_values=("FINANCE-PC",),
        )
        assert any("FINANCE-PC" in leak for leak in leaks)


# ---------------------------------------------------------------------------
# 8. sanitize_case integration — nested ECS case dict end-to-end
# ---------------------------------------------------------------------------


class TestSanitizeCaseIntegration:
    def test_full_case_dict_bare_names_removed(self) -> None:
        """End-to-end: ECS case dict with bare host + user + private IP."""
        m = _mapping()
        case = {
            "alert_summary": {
                "host_name": "FINANCE-PC",
                "user_name": "jsmith",
                "source_ip": "10.0.0.5",
                "destination_ip": "8.8.8.8",
                "message": "FINANCE-PC user jsmith triggered alert from 10.0.0.5",
                "rule_name": "ET MALWARE Beacon",
            },
            "loop_evidence": "Analyst noted FINANCE-PC is a known endpoint.",
            "local_verdict": "true_positive",
            "local_confidence": 0.9,
            "local_summary": "User jsmith on FINANCE-PC contacted C2.",
            "local_citations": ["host_name: FINANCE-PC", "user.name: jsmith"],
        }
        out = sanitize_case(case, m)
        text = json.dumps(out)

        # Bare names — gone everywhere.
        assert "FINANCE-PC" not in text
        assert "jsmith" not in text
        # Private IP — gone.
        assert "10.0.0.5" not in text
        # Public IP — preserved.
        assert "8.8.8.8" in text
        # ET rule — preserved.
        assert "ET MALWARE Beacon" in text
        # No residue (with known_values).
        leaks = unsafe_residue(text, known_values=tuple(m.reverse.values()))
        assert leaks == [], f"Unexpected residue: {leaks}"

    def test_zeek_conn_event_shape(self) -> None:
        """Zeek conn event shape: id.orig_h/id.resp_h + related.hosts."""
        m = _mapping()
        case = {
            "id": {"orig_h": "192.168.0.100", "resp_h": "1.2.3.4"},
            "host": {"name": "sensor-01"},
            "related": {"hosts": ["sensor-01", "WORKSTATION-9"]},
            "message": "conn from 192.168.0.100 to 1.2.3.4 host sensor-01",
        }
        out = sanitize_case(case, m)
        text = json.dumps(out)
        # Private orig_h → gone.
        assert "192.168.0.100" not in text
        # Public resp_h → preserved.
        assert "1.2.3.4" in text
        # Bare hostnames → gone.
        assert "sensor-01" not in text
        assert "WORKSTATION-9" not in text

    def test_roundtrip_with_desanitize(self) -> None:
        """sanitize_case → desanitize should restore bare names accurately."""
        from soc_ai.oracle.sanitize import desanitize

        m = _mapping()
        case = {
            "host_name": "FINANCE-PC",
            "user_name": "jsmith",
            "source_ip": "10.0.0.5",
        }
        out = sanitize_case(case, m)
        restored = desanitize(out, m)
        assert restored == case


# ---------------------------------------------------------------------------
# 8b. FIELD-MAP GAP — bare internal identity in a real-but-unmapped field LEAKS
# ---------------------------------------------------------------------------


class TestFieldMapGapLeaks:
    """Security regression tests: bare internal identifiers in protocol-identity
    fields that DO appear in the real ``EnrichedAlertContext.model_dump()`` case
    dict but were previously NOT in ``redact.py``'s field policy map.

    These fields (zeek_ssl_server_name / zeek_http_host / zeek_dns_query /
    dns_query) carry a *server identity*. On an internal-to-internal connection
    that identity is a BARE internal hostname (NetBIOS-style SNI, single-label
    mDNS/LLMNR query, intranet Host header) with no IP/suffix shape — so without
    explicit field-policy coverage Pass 1 never learns it, Pass 2 never propagates
    it, and ``known_values`` in the residue gate never knows it.
    """

    def test_bare_internal_sni_does_not_leak(self) -> None:
        """A bare internal SSL SNI (zeek_ssl_server_name) must not egress."""
        from soc_ai.so_client.models import SoAlert
        from soc_ai.tools.get_alert_context import EnrichedAlertContext

        m = _mapping()
        a = SoAlert(id="a1", host_name="SENSOR-01", zeek_ssl_server_name="FILESERVER")
        case = {"alert_summary": EnrichedAlertContext(alert=a).model_dump(mode="json")}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        leaks = unsafe_residue(text, known_values=tuple(m.reverse.values()))
        assert "FILESERVER" not in text, "bare internal SNI leaked to outbound payload"
        assert leaks == [], f"residue gate also missed it: {leaks}"

    def test_bare_internal_http_host_does_not_leak(self) -> None:
        """A bare internal HTTP Host header (zeek_http_host) must not egress."""
        from soc_ai.so_client.models import SoAlert
        from soc_ai.tools.get_alert_context import EnrichedAlertContext

        m = _mapping()
        a = SoAlert(id="a2", zeek_http_host="INTRANET")
        case = {"alert_summary": EnrichedAlertContext(alert=a).model_dump(mode="json")}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "INTRANET" not in text, "bare internal HTTP Host leaked to outbound payload"

    def test_bare_internal_dns_query_does_not_leak(self) -> None:
        """A bare single-label internal DNS query (dns_query) must not egress."""
        from soc_ai.so_client.models import SoAlert
        from soc_ai.tools.get_alert_context import EnrichedAlertContext

        m = _mapping()
        a = SoAlert(id="a3", dns_query="PRINTSRV")
        case = {"alert_summary": EnrichedAlertContext(alert=a).model_dump(mode="json")}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "PRINTSRV" not in text, "bare internal DNS query leaked to outbound payload"

    # -----------------------------------------------------------------------
    # Additional gating tests — public FQDNs pass; internal suffix tokenised
    # -----------------------------------------------------------------------

    def test_public_dotted_sni_passes(self) -> None:
        """Public FQDN in zeek_ssl_server_name → NOT tokenised (Oracle needs it)."""
        m = _mapping()
        case = {"alert": {"zeek_ssl_server_name": "mail.google.com"}}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "mail.google.com" in text, "public SNI must pass through verbatim"
        assert m.counters.get("HOST", 0) == 0

    def test_public_dotted_http_host_passes(self) -> None:
        """Public FQDN in zeek_http_host → NOT tokenised."""
        m = _mapping()
        case = {"alert": {"zeek_http_host": "evil.com"}}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "evil.com" in text
        assert m.counters.get("HOST", 0) == 0

    def test_public_dotted_dns_query_passes(self) -> None:
        """Public FQDN in zeek_dns_query → NOT tokenised."""
        m = _mapping()
        case = {"alert": {"zeek_dns_query": "cdc.gov"}}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "cdc.gov" in text
        assert m.counters.get("HOST", 0) == 0

    def test_internal_suffix_sni_tokenised(self) -> None:
        """zeek_ssl_server_name ending in .lan → tokenised."""
        m = _mapping()
        case = {"alert": {"zeek_ssl_server_name": "dc01.lan"}}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "dc01.lan" not in text
        assert "HOST_" in text

    def test_single_label_sni_tokenised(self) -> None:
        """Single-label zeek_ssl_server_name (PRINTSRV) → tokenised."""
        m = _mapping()
        case = {"alert": {"zeek_ssl_server_name": "PRINTSRV"}}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "PRINTSRV" not in text
        assert "HOST_" in text

    def test_typed_zeek_sni_servers_list_single_label(self) -> None:
        """typed_zeek.sni_servers list — single-label elements tokenised."""
        m = _mapping()
        case = {"typed_zeek": {"sni_servers": ["FILESERVER", "mail.google.com"]}}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "FILESERVER" not in text, "single-label SNI in list must be tokenised"
        assert "mail.google.com" in text, "public FQDN in SNI list must pass through"

    def test_typed_zeek_http_hosts_list_internal_suffix(self) -> None:
        """typed_zeek.http_hosts list — internal-suffix elements tokenised."""
        m = _mapping()
        case = {"typed_zeek": {"http_hosts": ["INTRANET", "intranet.corp", "evil.com"]}}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "INTRANET" not in text
        assert "intranet.corp" not in text
        assert "evil.com" in text

    def test_typed_zeek_dns_queries_list_mixed(self) -> None:
        """typed_zeek.dns_queries list — mixed single-label and public FQDNs."""
        m = _mapping()
        case = {"typed_zeek": {"dns_queries": ["PRINTSRV", "cdc.gov", "srv.local"]}}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "PRINTSRV" not in text
        assert "srv.local" not in text
        assert "cdc.gov" in text


# ---------------------------------------------------------------------------
# 8c. Short-token guard — learned values ≤3 chars do NOT corrupt public IOCs
# ---------------------------------------------------------------------------


class TestShortTokenGuard:
    """Learned host values of ≤3 chars (``dc``, ``ns1``, ``srv``) must NOT be
    propagated globally via the learned-re substitution — a 2-char learned host
    ``dc`` would silently corrupt ``dc.evil.com`` → ``HOST_01.evil.com``."""

    def test_short_learned_host_does_not_corrupt_public_domain(self) -> None:
        """A 2-char bare host (``dc``) must not corrupt a public domain containing it."""
        m = _mapping()
        # ``dns_query="dc"`` is single-label → tokenised in Pass 1 as HOST_01.
        # But ``dc.evil.com`` is a public domain and must survive Pass 2 intact.
        case = {
            "alert": {"zeek_dns_query": "dc"},
            "message": "Connection to dc.evil.com observed",
        }
        out = sanitize_case(case, m)
        text = json.dumps(out)
        # The short host must be tokenised in its structured field.
        assert "HOST_" in text, "short bare host must be tokenised in its own field"
        # The public domain must NOT be corrupted.
        assert "dc.evil.com" in text, (
            "public domain containing short host must not be corrupted by learned-re"
        )

    def test_short_learned_host_mail_does_not_corrupt_public_domain(self) -> None:
        """A 4-char bare host ``mail`` does corrupt since len(mail)==4 > 3 threshold.

        Conversely, a 2-char or 3-char value does NOT propagate globally.
        This tests the boundary: 3-char hosts are guarded, 4-char are not.
        """
        m = _mapping()
        # 3-char: ``srv`` — should NOT propagate globally.
        case = {
            "alert": {"zeek_dns_query": "srv"},
            "message": "Query for srv.corp resolved; also queried srv.company.com",
        }
        out = sanitize_case(case, m)
        text = json.dumps(out)
        # ``srv.company.com`` is a dotted public domain — must survive.
        assert "srv.company.com" in text, (
            "3-char learned host must not corrupt dotted public domain"
        )


# ---------------------------------------------------------------------------
# 8d. Field-map extension — host.hostname / host_hostname HOSTNAME aliases
# ---------------------------------------------------------------------------


class TestHostnameAliasFields:
    """The ECS ``host.hostname`` alias and its flat ``host_hostname`` form must
    be tokenised as HOST.  ``host_hostname`` (flat underscore alias from a
    model_dump) previously had NO field-policy coverage and leaked verbatim."""

    def test_host_hostname_flat_tokenised(self) -> None:
        """Flat ``host_hostname`` → HOST_n (was a leak before the field-map add)."""
        m = _mapping()
        case = {"host_hostname": "DESKTOP-AB12"}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "DESKTOP-AB12" not in text, "host_hostname must be tokenised"
        assert "HOST_" in text
        assert m.counters.get("HOST", 0) >= 1

    def test_host_hostname_nested_tokenised(self) -> None:
        """Nested ``host.hostname`` → HOST_n."""
        m = _mapping()
        case = {"host": {"hostname": "WIN-7G3K9J2"}}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "WIN-7G3K9J2" not in text
        assert "HOST_" in text


# ---------------------------------------------------------------------------
# 8e. Pattern-based NetBIOS/Windows bare-hostname catch in FREE-TEXT fields
# ---------------------------------------------------------------------------


class TestNetbiosFreeTextRedaction:
    """A NetBIOS/Windows-style bare hostname (DESKTOP-AB12, WIN-7G3K9J2,
    FINANCE-PC, RECEPTION-LAPTOP) that appears ONLY in a free-text field
    (``message``) — with no structured host field to learn it from — must still
    be tokenised by the conservative pattern matcher, AND must round-trip.

    Negative coverage proves the conservatism: public domains, rule/signature
    names, dictionary words, and product strings are NOT redacted.
    """

    # --- positive: structural prefix forms ---------------------------------

    def test_desktop_prefix_in_message_redacted(self) -> None:
        m = _mapping()
        case = {"message": "Interactive logon from DESKTOP-AB12 observed"}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "DESKTOP-AB12" not in text, "bare DESKTOP- hostname must be redacted"
        assert "HOST_" in text

    def test_win_prefix_in_message_redacted(self) -> None:
        m = _mapping()
        case = {"message": "host WIN-7G3K9J2 contacted C2"}
        out = sanitize_case(case, m)
        assert "WIN-7G3K9J2" not in json.dumps(out)

    # --- positive: structural suffix forms ---------------------------------

    def test_pc_suffix_in_message_redacted(self) -> None:
        m = _mapping()
        case = {"message": "alert raised on FINANCE-PC at 02:00"}
        out = sanitize_case(case, m)
        assert "FINANCE-PC" not in json.dumps(out)

    def test_laptop_suffix_in_message_redacted(self) -> None:
        m = _mapping()
        case = {"message": "RECEPTION-LAPTOP failed kerberos preauth"}
        out = sanitize_case(case, m)
        assert "RECEPTION-LAPTOP" not in json.dumps(out)

    # --- round-trip --------------------------------------------------------

    def test_netbios_freetext_roundtrips(self) -> None:
        """Pattern-detected names rehydrate to the exact original bytes."""
        from soc_ai.oracle.sanitize import desanitize

        m = _mapping()
        case = {"message": "Logon from DESKTOP-AB12 to FINANCE-PC"}
        out = sanitize_case(case, m)
        restored = desanitize(out, m)
        assert restored == case, "pattern-detected hostnames must round-trip exactly"

    def test_netbios_freetext_consistent_label(self) -> None:
        """Same bare host in two free-text spots → one stable HOST_n label."""
        m = _mapping()
        case = {
            "message": "DESKTOP-AB12 logged on",
            "loop_evidence": "DESKTOP-AB12 then ran mimikatz",
        }
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "DESKTOP-AB12" not in text
        # Exactly one HOST allocation for the single distinct surface form.
        assert m.counters.get("HOST", 0) == 1

    # --- negative: public domains / rules / words / products NOT redacted --

    def test_public_domain_not_redacted(self) -> None:
        """A public domain (has a dot) is NEVER matched by the bare-host net."""
        m = _mapping()
        case = {"message": "C2 callback to example.com and to win-rar.com"}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "example.com" in text
        assert "win-rar.com" in text
        assert m.counters.get("HOST", 0) == 0

    def test_public_domain_with_affix_label_not_redacted(self) -> None:
        """A dotted FQDN whose first label looks like an affix (desktop-…) passes."""
        m = _mapping()
        case = {"message": "served from desktop-themes.microsoft.com"}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "desktop-themes.microsoft.com" in text
        assert m.counters.get("HOST", 0) == 0

    def test_rule_name_in_message_not_redacted(self) -> None:
        """ET/GPL rule strings in free text are not bare hostnames."""
        m = _mapping()
        case = {"message": "ET MALWARE BPFDoor Beacon; GPL ATTACK_RESPONSE id check"}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "ET MALWARE BPFDoor Beacon" in text
        assert "ATTACK_RESPONSE" in text, "underscore affix must not match hyphen pattern"
        assert m.counters.get("HOST", 0) == 0

    def test_dictionary_word_malware_not_redacted(self) -> None:
        """The plain word 'malware' must survive (Oracle reasoning relies on it)."""
        m = _mapping()
        case = {"message": "suspected malware activity on the segment"}
        out = sanitize_case(case, m)
        assert "malware" in json.dumps(out)
        assert m.counters.get("HOST", 0) == 0

    def test_product_strings_not_redacted(self) -> None:
        """Vendor/product strings must pass through verbatim."""
        m = _mapping()
        case = {"message": "Windows PowerShell with Endpoint-Protection enabled"}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "Windows" in text
        assert "PowerShell" in text
        # 'Endpoint-Protection' uses an affix NOT in our allow-set → not matched.
        assert "Endpoint-Protection" in text
        assert m.counters.get("HOST", 0) == 0

    def test_bare_win_word_not_redacted(self) -> None:
        """'WIN' with no hyphen-affix is a word, not a NetBIOS name → passes."""
        m = _mapping()
        case = {"message": "read about the WIN32 API and the WIN architecture"}
        out = sanitize_case(case, m)
        text = json.dumps(out)
        assert "WIN32" in text
        assert "WIN architecture" in text
        assert m.counters.get("HOST", 0) == 0


# ---------------------------------------------------------------------------
# 9. Client-level test: bare host in host.name + message → HOST_n in payload
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_client_bare_host_in_host_name_and_message_redacted() -> None:
    """adjudicate: case with bare host in host_name + message → payload contains
    only HOST_n, never the raw bare name."""
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import EnrichedAlertContext

    settings = _make_settings()
    ctx = _make_ctx(settings)

    enriched = EnrichedAlertContext(
        alert=SoAlert(
            id="alert-finance-01",
            severity_label="high",
            source_ip="10.0.0.5",
            destination_ip="8.8.8.8",
            host_name="FINANCE-PC",
            user_name="jsmith",
            message="FINANCE-PC: user jsmith triggered alert from 10.0.0.5",
        ),
        community_id_events=[],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
    )

    import json as _json

    captured_payloads: list[str] = []

    async def _capture(payload: str, *, settings: Any) -> str:
        captured_payloads.append(payload)
        return _json.dumps(
            {
                "verdict": "false_positive",
                "confidence": 0.85,
                "summary": "Test summary.",
                "reasoning": "No malicious activity detected.",
            }
        )

    with patch("soc_ai.oracle.client._call_oracle_raw", _capture):
        result = await adjudicate(
            ctx,
            enriched=enriched,
            local_report=_stub_report(),
            transcript_text="Evidence: FINANCE-PC ran mimikatz; user jsmith exfil'd data.",
        )

    # Adjudication must succeed (not refused).
    assert result is not None, "adjudicate should succeed — all PII was redacted"
    assert isinstance(result, OracleResult)

    # One payload must have been sent.
    assert len(captured_payloads) == 1
    payload = captured_payloads[0]

    # Bare names must NOT appear in the outbound payload.
    assert "FINANCE-PC" not in payload, "bare hostname must be redacted before egress"
    assert "jsmith" not in payload, "bare username must be redacted before egress"
    # Private IP must also be gone.
    assert "10.0.0.5" not in payload, "private IP must be redacted before egress"

    # Opaque tokens must be present.
    assert "HOST_" in payload, "HOST_n token must appear in payload"
    assert "USER_" in payload, "USER_n token must appear in payload"
    assert "IP_" in payload, "IP_n token must appear in payload"

    # Public IP must survive.
    assert "8.8.8.8" in payload, "public IP must pass through"


@pytest.mark.asyncio
async def test_client_known_values_residue_refuses() -> None:
    """adjudicate REFUSES when a learned value survives to the payload.

    Simulate sanitize_case returning a partially-redacted dict where the bare
    hostname survived.  unsafe_residue with known_values should catch it and
    the call must return None without touching the model.
    """
    settings = _make_settings()
    ctx = _make_ctx(settings)

    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import EnrichedAlertContext

    enriched = EnrichedAlertContext(
        alert=SoAlert(id="alert-refuse-01", severity_label="low"),
        community_id_events=[],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
    )

    # Patch sanitize_case to return a dict that still contains the bare hostname.
    leaking_case: dict[str, Any] = {
        "alert_summary": {
            "host_name": "HOST_01",  # hostname already tokenised
            "message": "FINANCE-PC triggered something",  # ← LEAK: raw value survived
        }
    }

    # We also need the mapping to have FINANCE-PC → HOST_01 so known_values
    # triggers.  Build a real Mapping and patch it in via the sanitize_case mock.
    from soc_ai.oracle.redact import Mapping as RedactMapping

    def _fake_sanitize_case(
        case: dict[str, Any],
        mapping: RedactMapping,
        **_kwargs: Any,
    ) -> dict[str, Any]:
        # Simulate the harvest that would have occurred.
        mapping.label_for("FINANCE-PC", "HOST")
        return leaking_case

    raw_call = AsyncMock()

    with (
        patch("soc_ai.oracle.client.sanitize_case", side_effect=_fake_sanitize_case),
        patch("soc_ai.oracle.client._call_oracle_raw", raw_call),
    ):
        result = await adjudicate(
            ctx,
            enriched=enriched,
            local_report=_stub_report(),
            transcript_text="",
        )

    # Must refuse — FINANCE-PC survived in the payload.
    assert result is None, "adjudicate must refuse when known value leaked to payload"
    raw_call.assert_not_awaited()


# ---------------------------------------------------------------------------
# 10. Increment 2c — sanitizer consumes the effective internal-identifier set
#
# These exercise the REAL orchestrator-layer wiring: the effective set is
# resolved from the internal_identifier table at the caller and threaded into
# adjudicate() as extra_suffixes / extra_hosts. The sanitizer stays pure (it
# receives resolved tuples), and a db-less / empty-table path falls back to the
# raw settings tuples so behavior is unchanged.
# ---------------------------------------------------------------------------


async def _make_db(
    settings: Settings,
) -> tuple[Any, Any]:
    """Create a migrated one-off store + sessionmaker (mirrors test_internal_identifiers)."""
    from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


def _enriched_with_host(host_fqdn: str) -> Any:
    """An EnrichedAlertContext whose free-text message carries *host_fqdn*."""
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import EnrichedAlertContext

    return EnrichedAlertContext(
        alert=SoAlert(
            id="alert-corp-01",
            severity_label="high",
            source_ip="10.0.0.9",
            destination_ip="8.8.8.8",
            rule_name="Connection to internal host",
            message=f"Beacon from {host_fqdn} to 8.8.8.8 observed",
        ),
        community_id_events=[],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
    )


async def _capture_payload_via_adjudicate(
    ctx: Any,
    *,
    enriched: Any,
    extra_hosts: tuple[str, ...] | None,
    extra_suffixes: tuple[str, ...] | None,
    transcript_text: str = "",
) -> list[str]:
    """Run adjudicate() with the gateway patched, returning the captured payload(s)."""
    captured: list[str] = []

    async def _capture(payload: str, *, settings: Any) -> str:
        captured.append(payload)
        return json.dumps(
            {
                "verdict": "false_positive",
                "confidence": 0.8,
                "summary": "Test summary.",
                "reasoning": "Benign.",
            }
        )

    with patch("soc_ai.oracle.client._call_oracle_raw", _capture):
        result = await adjudicate(
            ctx,
            enriched=enriched,
            local_report=_stub_report(),
            transcript_text=transcript_text,
            extra_hosts=extra_hosts,
            extra_suffixes=extra_suffixes,
        )
    assert result is not None, "adjudicate should succeed (payload fully sanitized)"
    return captured


@pytest.mark.asyncio
async def test_effective_active_suffix_redacts_via_real_path(
    settings_kratos: Settings,
) -> None:
    """A detected/active ``.corp.acme.com`` suffix row → an FQDN on that suffix is
    redacted by the REAL Oracle sanitization path (resolver → adjudicate)."""
    from soc_ai.oracle.identifiers import effective_internal_identifiers
    from soc_ai.store import internal_identifiers as ids

    settings = settings_kratos
    engine, maker = await _make_db(settings)
    try:
        async with maker() as db:
            await ids.upsert_detected(db, "suffix", ".corp.acme.com", {"x": 1}, "active")
            effective = await effective_internal_identifiers(db, settings)
    finally:
        await engine.dispose()

    # The resolver included the detected suffix (over and above env defaults).
    assert ".corp.acme.com" in effective.suffixes

    ctx = _make_ctx(settings)
    captured = await _capture_payload_via_adjudicate(
        ctx,
        enriched=_enriched_with_host("dc01.corp.acme.com"),
        extra_hosts=effective.hosts,
        extra_suffixes=effective.suffixes,
    )
    payload = captured[0]
    assert "dc01.corp.acme.com" not in payload, (
        "FQDN on an active detected suffix must be redacted before egress"
    )
    assert "HOST_" in payload, "the internal FQDN must become a HOST_n token"
    assert "8.8.8.8" in payload, "public IP must still pass through"


@pytest.mark.asyncio
async def test_muted_suffix_not_redacted_defaults_still_apply(
    settings_kratos: Settings,
) -> None:
    """With the ``.corp.acme.com`` row muted, an FQDN on it is NOT redacted — but a
    reserved-default suffix FQDN (``.lan``) still is."""
    from soc_ai.oracle.identifiers import effective_internal_identifiers
    from soc_ai.store import internal_identifiers as ids

    settings = settings_kratos
    engine, maker = await _make_db(settings)
    try:
        async with maker() as db:
            row = await ids.upsert_detected(db, "suffix", ".corp.acme.com", {"x": 1}, "active")
            await ids.set_state(db, row.id, "muted")
            effective = await effective_internal_identifiers(db, settings)
    finally:
        await engine.dispose()

    assert ".corp.acme.com" not in effective.suffixes  # muted → subtracted
    assert ".lan" in effective.suffixes  # reserved default survives

    ctx = _make_ctx(settings)
    captured = await _capture_payload_via_adjudicate(
        ctx,
        enriched=_enriched_with_host("dc01.corp.acme.com"),
        extra_hosts=effective.hosts,
        extra_suffixes=effective.suffixes,
        # Add a .lan host so we can assert the reserved default still redacts.
        transcript_text="Also saw fileserver.lan in the same window.",
    )
    payload = captured[0]
    # Muted suffix → the FQDN egresses verbatim (operator suppressed it).
    assert "dc01.corp.acme.com" in payload, "an FQDN on a MUTED suffix must NOT be redacted"
    # Reserved default (.lan) is untouched by the mute → still redacted.
    assert "fileserver.lan" not in payload, "a reserved-default suffix must still redact"
    assert "HOST_" in payload, "the .lan host must become a HOST_n token"


@pytest.mark.asyncio
async def test_muting_a_reserved_default_is_ignored_floor_wins(
    settings_kratos: Settings,
) -> None:
    """Safety net: muting a row whose value IS a reserved default (``.lan``) has no
    net effect — the sanitizer floor (``_resolve_suffixes`` always prepends
    ``settings.oracle_internal_suffixes`` / the reserved ``_DEFAULT_SUFFIXES``)
    re-adds it, so a ``*.lan`` host is STILL redacted before egress.

    This documents the security contract: reserved special-use suffixes cannot be
    muted away via the internal_identifier table (fail-safe over-redaction).
    """
    from soc_ai.oracle.identifiers import effective_internal_identifiers
    from soc_ai.store import internal_identifiers as ids

    settings = settings_kratos
    engine, maker = await _make_db(settings)
    try:
        async with maker() as db:
            # A detected ``.lan`` row that the operator has muted.
            row = await ids.upsert_detected(db, "suffix", ".lan", {"x": 1}, "active")
            await ids.set_state(db, row.id, "muted")
            effective = await effective_internal_identifiers(db, settings)
    finally:
        await engine.dispose()

    # The resolver subtracts the muted ``.lan`` from its own merged output …
    assert ".lan" not in effective.suffixes, (
        "resolver subtracts the muted value from its merged set"
    )

    # … but the egress sanitizer re-adds the reserved/env default as a floor, so
    # a ``*.lan`` host run through the REAL adjudicate→sanitize path is STILL
    # redacted. The floor wins.
    ctx = _make_ctx(settings)
    captured = await _capture_payload_via_adjudicate(
        ctx,
        enriched=_enriched_with_host("dc01.corp.acme.com"),
        extra_hosts=effective.hosts,
        extra_suffixes=effective.suffixes,
        transcript_text="Also saw fileserver.lan in the same window.",
    )
    payload = captured[0]
    assert "fileserver.lan" not in payload, (
        "muting a reserved-default suffix must NOT disable its redaction — the "
        "sanitizer floor re-adds it (fail-safe)"
    )
    assert "HOST_" in payload, "the .lan host must still become a HOST_n token"
    assert "8.8.8.8" in payload, "public IP must still pass through"


@pytest.mark.asyncio
async def test_backward_compat_empty_table_matches_settings_only(
    settings_kratos: Settings,
) -> None:
    """With NO internal_identifier rows, threading the resolver output is identical
    to the pre-change settings-only behavior: the env-config suffixes/hosts still
    redact, and passing None (db-less path) yields the same payload."""
    from soc_ai.oracle.identifiers import effective_internal_identifiers
    from soc_ai.store import internal_identifiers as ids

    # An operator who set ORACLE_INTERNAL_SUFFIXES / ORACLE_EXTRA_HOSTS via env.
    settings = _make_settings(
        oracle_internal_suffixes=[".lan", ".local", ".internal", ".corp", ".myco.example"],
        oracle_extra_hosts=["WIN11-01"],
    )

    engine, maker = await _make_db(settings)
    try:
        async with maker() as db:
            assert await ids.list_identifiers(db) == []  # empty table
            effective = await effective_internal_identifiers(db, settings)
    finally:
        await engine.dispose()

    # Empty table ⇒ effective set is exactly the env-config set.
    assert effective.suffixes == (".lan", ".local", ".internal", ".corp", ".myco.example")
    assert effective.hosts == ("WIN11-01",)

    enriched = _enriched_with_host("host.myco.example")
    transcript = "WIN11-01 contacted host.myco.example"

    ctx = _make_ctx(settings)
    # Path A: db-less / None → adjudicate falls back to settings tuples.
    fallback_payload = (
        await _capture_payload_via_adjudicate(
            ctx,
            enriched=enriched,
            extra_hosts=None,
            extra_suffixes=None,
            transcript_text=transcript,
        )
    )[0]
    # Path B: resolver output from an empty table.
    resolved_payload = (
        await _capture_payload_via_adjudicate(
            ctx,
            enriched=enriched,
            extra_hosts=effective.hosts,
            extra_suffixes=effective.suffixes,
            transcript_text=transcript,
        )
    )[0]

    # The env-config suffix + host both redact on BOTH paths.
    for payload in (fallback_payload, resolved_payload):
        assert "host.myco.example" not in payload, "env-config suffix must redact"
        assert "WIN11-01" not in payload, "env-config extra_host must redact"
        assert "HOST_" in payload

    # And the two payloads are identical — threading the empty-table resolver
    # output changes nothing vs. the settings-only fallback.
    assert fallback_payload == resolved_payload


# ---------------------------------------------------------------------------
# 11. Orchestrator-layer resolver: db-less ctx falls back; ctx-with-db resolves.
# ---------------------------------------------------------------------------


def _real_ctx(settings: Settings, *, maker: Any = None) -> Any:
    """A real InvestigationContext with the minimum fields the resolver touches."""
    from unittest.mock import MagicMock as _MM

    from soc_ai.agent.orchestrator import InvestigationContext

    return InvestigationContext(
        settings=settings,
        auth=_MM(),
        elastic=_MM(),
        db_sessionmaker=maker,
    )


@pytest.mark.asyncio
async def test_resolver_returns_none_when_no_db(settings_kratos: Settings) -> None:
    """No db_sessionmaker on ctx → resolver returns None (→ client uses settings)."""
    from soc_ai.agent.orchestrator import _resolve_oracle_identifiers

    ctx = _real_ctx(settings_kratos, maker=None)
    assert await _resolve_oracle_identifiers(ctx) is None


@pytest.mark.asyncio
async def test_resolver_returns_effective_tuples_with_db(
    settings_kratos: Settings,
) -> None:
    """With a db_sessionmaker + an active detected suffix, the resolver returns the
    effective (suffixes, hosts), including the detected suffix and a manual host."""
    from soc_ai.agent.orchestrator import _resolve_oracle_identifiers
    from soc_ai.store import internal_identifiers as ids

    settings = settings_kratos
    engine, maker = await _make_db(settings)
    try:
        async with maker() as db:
            await ids.upsert_detected(db, "suffix", ".corp.acme.com", {"x": 1}, "active")
            await ids.add_manual(db, "host", "WIN11-01")

        ctx = _real_ctx(settings, maker=maker)
        resolved = await _resolve_oracle_identifiers(ctx)
    finally:
        await engine.dispose()

    assert resolved is not None
    suffixes, hosts = resolved
    assert ".corp.acme.com" in suffixes
    assert ".lan" in suffixes  # env defaults still present
    assert "WIN11-01" in hosts


# ---------------------------------------------------------------------------
# Increment 3: effective-CIDR classification wire-in (orchestrator layer)
# ---------------------------------------------------------------------------
#
# Internal-IP classification at the orchestrator consumes the EFFECTIVE CIDR set
# (settings.internal_cidrs union active 'cidr' rows minus muted) resolved once
# per investigation, falling back to settings.internal_cidrs when there is no DB
# (CLI / eval / tests) or resolution fails. With no active 'cidr' rows the
# effective cidrs are byte-identical to settings.internal_cidrs.


def _narrow_settings(settings_kratos: Settings) -> Settings:
    """settings with internal_cidrs = 192.168/16 ONLY (so 10.x is EXTERNAL)."""
    from ipaddress import IPv4Network

    return settings_kratos.model_copy(update={"internal_cidrs": [IPv4Network("192.168.0.0/16")]})


@pytest.mark.asyncio
async def test_classification_cidrs_db_less_falls_back_to_settings(
    settings_kratos: Settings,
) -> None:
    """No db_sessionmaker → _resolve_effective_identifiers is None and
    _classification_cidrs returns settings.internal_cidrs unchanged."""
    from soc_ai.agent.orchestrator import (
        _classification_cidrs,
        _resolve_effective_identifiers,
    )

    settings = _narrow_settings(settings_kratos)
    ctx = _real_ctx(settings, maker=None)
    assert await _resolve_effective_identifiers(ctx) is None
    cidrs = _classification_cidrs(ctx, None)
    assert list(cidrs) == list(settings.internal_cidrs)


@pytest.mark.asyncio
async def test_classification_cidrs_empty_table_matches_settings_only(
    settings_kratos: Settings,
) -> None:
    """With a DB but NO 'cidr' rows, the effective cidrs == settings.internal_cidrs
    (backward-compat: classification unchanged)."""
    from soc_ai.agent.orchestrator import (
        _classification_cidrs,
        _resolve_effective_identifiers,
    )

    settings = _narrow_settings(settings_kratos)
    engine, maker = await _make_db(settings)
    try:
        ctx = _real_ctx(settings, maker=maker)
        effective = await _resolve_effective_identifiers(ctx)
    finally:
        await engine.dispose()

    assert effective is not None
    cidrs = _classification_cidrs(ctx, effective)
    assert [str(n) for n in cidrs] == [str(n) for n in settings.internal_cidrs]


@pytest.mark.asyncio
async def test_active_cidr_row_classifies_inside_ip_internal(
    settings_kratos: Settings,
) -> None:
    """An ACTIVE 'cidr' row adds its network to the effective set, so an IP inside
    it classifies internal — while it was EXTERNAL under settings-only."""
    import ipaddress

    from soc_ai.agent.orchestrator import (
        _classification_cidrs,
        _resolve_effective_identifiers,
    )
    from soc_ai.store import internal_identifiers as ids

    settings = _narrow_settings(settings_kratos)  # 192.168/16 only → 10.50.0.5 external
    engine, maker = await _make_db(settings)
    try:
        async with maker() as db:
            # Discovery always suggests muted; the operator un-mutes to activate.
            await ids.upsert_detected(db, "cidr", "10.50.0.0/24", {"host_count": 4}, "muted")
            await ids.add_manual(db, "cidr", "10.50.0.0/24")  # un-mute → active
        ctx = _real_ctx(settings, maker=maker)
        effective = await _resolve_effective_identifiers(ctx)
    finally:
        await engine.dispose()

    assert effective is not None
    cidrs = _classification_cidrs(ctx, effective)
    target = ipaddress.ip_address("10.50.0.5")
    # Internal under the EFFECTIVE set (the active row added 10.50.0.0/24)...
    assert any(target in net for net in cidrs)
    # ...but EXTERNAL under settings-only (192.168/16) — proving the overlay matters.
    assert not any(target in net for net in settings.internal_cidrs)


@pytest.mark.asyncio
async def test_muted_cidr_row_does_not_classify_inside_ip_internal(
    settings_kratos: Settings,
) -> None:
    """A MUTED 'cidr' row (the suggest-first default) does NOT add its network —
    so an IP inside it stays external. No count makes a discovered CIDR active."""
    import ipaddress

    from soc_ai.agent.orchestrator import (
        _classification_cidrs,
        _resolve_effective_identifiers,
    )
    from soc_ai.store import internal_identifiers as ids

    settings = _narrow_settings(settings_kratos)
    engine, maker = await _make_db(settings)
    try:
        async with maker() as db:
            await ids.upsert_detected(db, "cidr", "10.50.0.0/24", {"host_count": 9999}, "muted")
        ctx = _real_ctx(settings, maker=maker)
        effective = await _resolve_effective_identifiers(ctx)
    finally:
        await engine.dispose()

    assert effective is not None
    cidrs = _classification_cidrs(ctx, effective)
    target = ipaddress.ip_address("10.50.0.5")
    assert not any(target in net for net in cidrs), (
        "a MUTED (suggested) CIDR must not reclassify a host as internal"
    )


class TestDnsSdFreeText:
    """Incident 2026-07-08: DNS-SD service FQDNs in free-text fields must be
    redacted by sanitize_case's shape rules (Pass 2 → _sanitize_str)."""

    def test_incident_strings_redacted_via_sanitize_case(self) -> None:
        m = Mapping()
        case = {
            "alert": {"payload_printable": "2~..........._aaplcache1._tcp.corp.lan....."},
            "network": {"data": {"decoded": ".C..........\n_aaplcache._tcp.corp.lan....."}},
            "message": "mDNS query for _aaplcache._tcp.corp.lan observed",
        }
        out = sanitize_case(case, m)
        outbound = json.dumps(out)
        assert "aaplcache" not in outbound
        assert "corp.lan" not in outbound
        assert unsafe_residue(outbound) == []
