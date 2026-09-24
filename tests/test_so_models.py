"""Tests for :mod:`soc_ai.so_client.models`."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from soc_ai.so_client.models import (
    SoAlert,
    SoCase,
    SoDetection,
    SoPlaybook,
    _parse_iso,
    get_dotted,
)

# ---- get_dotted helper -------------------------------------------------


def test_get_dotted_nested() -> None:
    d = {"a": {"b": {"c": 42}}}
    assert get_dotted(d, "a.b.c") == 42


def test_get_dotted_flat() -> None:
    d = {"a.b.c": 42}
    assert get_dotted(d, "a.b.c") == 42


def test_get_dotted_missing_segment_returns_none() -> None:
    d: dict[str, Any] = {"a": {"b": {}}}
    assert get_dotted(d, "a.b.c") is None
    assert get_dotted(d, "x.y.z") is None


def test_get_dotted_non_dict_mid_path_returns_none() -> None:
    d: dict[str, Any] = {"a": "not-a-dict"}
    assert get_dotted(d, "a.b") is None


def test_get_dotted_top_level_key() -> None:
    assert get_dotted({"foo": "bar"}, "foo") == "bar"


# ---- SoAlert -----------------------------------------------------------


def test_alert_from_es_hit_happy_path(sample_alert: dict[str, Any]) -> None:
    alert = SoAlert.from_es_hit(sample_alert)
    assert alert.id == "alert-001"
    assert alert.rule_name == "ET MALWARE Suspicious User-Agent"
    assert alert.rule_uuid == "rule-abc-123"
    assert alert.severity_label == "high"
    assert alert.severity_score == 75
    assert alert.network_community_id == "1:abc123def456=="
    assert alert.source_ip == "192.168.1.50"
    assert alert.source_port == 49152
    assert alert.destination_ip == "203.0.113.10"
    assert alert.destination_port == 443
    assert alert.host_name == "workstation-01"
    assert alert.host_ip == ["192.168.1.50", "fe80::1"]
    assert alert.user_name == "alice"
    assert alert.process_entity_id == "proc-abc-123"
    assert alert.file_hash_sha256.startswith("deadbeef")
    assert alert.message is not None
    assert "alert" in alert.tags
    assert alert.timestamp == datetime(2026, 5, 7, 10, 30, 0, 123000, tzinfo=UTC)


def test_alert_preserves_raw_source(sample_alert: dict[str, Any]) -> None:
    alert = SoAlert.from_es_hit(sample_alert)
    assert alert.raw == sample_alert["_source"]
    # Raw lets callers reach fields the typed view doesn't surface.
    assert alert.raw["event"]["kind"] == "alert"


def test_alert_with_minimal_doc() -> None:
    hit = {"_id": "alert-min", "_source": {}}
    alert = SoAlert.from_es_hit(hit)
    assert alert.id == "alert-min"
    assert alert.rule_name is None
    assert alert.host_ip == []
    assert alert.tags == []


def test_alert_host_ip_string_normalized_to_list() -> None:
    hit = {
        "_id": "alert-x",
        "_source": {"host": {"ip": "10.0.0.1"}},
    }
    alert = SoAlert.from_es_hit(hit)
    assert alert.host_ip == ["10.0.0.1"]


def test_alert_with_flat_dotted_source() -> None:
    """SO sometimes flattens ECS keys; both forms must work."""
    hit = {
        "_id": "alert-flat",
        "_source": {
            "@timestamp": "2026-05-07T10:30:00Z",
            "rule.name": "ET PROBE",
            "network.community_id": "1:flat==",
        },
    }
    alert = SoAlert.from_es_hit(hit)
    assert alert.rule_name == "ET PROBE"
    assert alert.network_community_id == "1:flat=="


# ---- Typed Suricata fields (issue #10) ---------------------------------


def test_alert_parses_rule_metadata_from_real_suricata_shape() -> None:
    """Suricata rule.metadata wraps every field in a single-element list.
    The model must unwrap and expose them as flat strings."""
    hit = {
        "_id": "et-info",
        "_source": {
            "@timestamp": "2026-05-08T22:35:16Z",
            "rule": {
                "name": "ET INFO CMS Hosting Domain",
                "metadata": {
                    "signature_severity": ["Informational"],
                    "attack_target": ["Client_Endpoint"],
                    "confidence": ["High"],
                    "deployment": ["Perimeter"],
                    "performance_impact": ["Low"],
                    "tag": ["Description_Generated_By_Proofpoint"],
                },
            },
        },
    }
    alert = SoAlert.from_es_hit(hit)
    assert alert.rule_metadata is not None
    assert alert.rule_metadata.signature_severity == "Informational"
    assert alert.rule_metadata.attack_target == "Client_Endpoint"
    assert alert.rule_metadata.confidence == "High"
    assert alert.rule_metadata.deployment == "Perimeter"
    assert alert.rule_metadata.performance_impact == "Low"
    assert alert.rule_metadata.metadata_tags == ["Description_Generated_By_Proofpoint"]
    # The is_informational property is the routing signal for issue #13.
    assert alert.rule_metadata.is_informational is True


def test_alert_rule_metadata_is_none_when_block_absent() -> None:
    """Most Zeek/audit events don't have rule.metadata; should be None,
    not an empty model."""
    hit = {"_id": "x", "_source": {"@timestamp": "2026-05-08T00:00:00Z"}}
    alert = SoAlert.from_es_hit(hit)
    assert alert.rule_metadata is None


def test_alert_rule_metadata_is_informational_handles_case_variations() -> None:
    """The fast-path routing should match `Informational`, `informational`,
    and stripped whitespace; otherwise typo-driven false negatives slip
    through."""
    for variant in ("Informational", "informational", "  Informational ", "INFORMATIONAL"):
        hit = {
            "_id": "x",
            "_source": {
                "rule": {"metadata": {"signature_severity": [variant]}},
            },
        }
        alert = SoAlert.from_es_hit(hit)
        assert alert.rule_metadata is not None
        assert alert.rule_metadata.is_informational is True, f"failed on {variant!r}"


def test_alert_rule_metadata_is_informational_false_for_other_severities() -> None:
    for sev in ("Major", "Critical", "Minor", None):
        hit = {
            "_id": "x",
            "_source": {
                "rule": {"metadata": {"signature_severity": [sev] if sev else []}},
            },
        }
        alert = SoAlert.from_es_hit(hit)
        if alert.rule_metadata is not None:
            assert alert.rule_metadata.is_informational is False


def test_alert_parses_dns_query_only_for_zeek_dns_events() -> None:
    """Issue #20 polluted-source guard: SO's ingest pipeline stuffs the
    rule's `content:` match into Suricata's top-level `dns.query_name`
    regardless of rule type, so we ONLY trust that field on Zeek DNS
    events. For Zeek dns docs, the field is the actual queried name."""
    hit = {
        "_id": "zeek-dns-1",
        "_source": {
            "event": {"dataset": "zeek.dns"},
            "dns": {"query_name": "storyblok.com", "rcode_name": "NOERROR"},
        },
    }
    alert = SoAlert.from_es_hit(hit)
    assert alert.dns_query == "storyblok.com"
    assert alert.dns_rcode_name == "NOERROR"


def test_alert_does_not_populate_dns_query_for_suricata_alert() -> None:
    """The known SO bug: Suricata alerts have `dns.query_name` set to
    the rule's `content:` match (e.g. `'POST'` on a "POST on unusual
    port" rule, hex bytes on shellcode rules). Skipping this prevents
    the agent from citing rule-content as evidence of a DNS query."""
    hit = {
        "_id": "suricata-alert-1",
        "_source": {
            "event": {"dataset": "suricata.alert"},
            "rule": {"name": "ET INFO HTTP POST on unusual Port"},
            # SO's pipeline put "POST" here even though the rule isn't DNS.
            "dns": {"query_name": "POST"},
        },
    }
    alert = SoAlert.from_es_hit(hit)
    assert alert.dns_query is None  # polluted source ignored
    assert alert.dns_rcode_name is None


def test_alert_payload_printable_from_message_json() -> None:
    """Issue #20: surface Suricata's `payload_printable` (the actual
    matched packet bytes rendered as text) so the model sees what
    triggered the alert, not just the rule name."""
    msg = (
        '{"event_type":"alert","alert":{"signature_id":2048555},'
        '"payload_printable":"a-us.storyblok.com....."}'
    )
    hit = {
        "_id": "x",
        "_source": {"event": {"dataset": "suricata.alert"}, "message": msg},
    }
    alert = SoAlert.from_es_hit(hit)
    assert alert.payload_printable == "a-us.storyblok.com....."


def test_alert_payload_printable_top_level_fallback() -> None:
    """Some Suricata events surface payload_printable at the top
    level instead of inside `message`. Both should work."""
    hit = {
        "_id": "x",
        "_source": {
            "event": {"dataset": "suricata.alert"},
            "payload_printable": "GET /robots.txt HTTP/1.1\\r\\nHost:",
        },
    }
    alert = SoAlert.from_es_hit(hit)
    assert alert.payload_printable.startswith("GET /robots.txt")


def test_alert_typed_zeek_conn_fields() -> None:
    """Issue #20: Zeek conn events surface the connection state and
    duration as first-class fields so the agent doesn't need to parse
    `zeek.conn.*` paths manually."""
    hit = {
        "_id": "z1",
        "_source": {
            "event": {"dataset": "zeek.conn"},
            "zeek": {
                "conn": {
                    "conn_state": "S0",
                    "history": "S",
                    "duration": 0.123,
                }
            },
        },
    }
    alert = SoAlert.from_es_hit(hit)
    assert alert.zeek_conn_state == "S0"
    assert alert.zeek_conn_history == "S"
    assert alert.zeek_conn_duration == 0.123


def test_alert_typed_zeek_dns_fields() -> None:
    """Zeek DNS events expose query/rcode/rejected for cite-by-path."""
    hit = {
        "_id": "z2",
        "_source": {
            "event": {"dataset": "zeek.dns"},
            "zeek": {"dns": {"query": ["example.com"], "rcode_name": "NOERROR", "rejected": False}},
        },
    }
    alert = SoAlert.from_es_hit(hit)
    assert alert.zeek_dns_query == "example.com"
    assert alert.zeek_dns_rcode_name == "NOERROR"
    assert alert.zeek_dns_rejected is False


def test_alert_typed_zeek_ssl_and_http_fields() -> None:
    """SSL server_name and HTTP host/method/status for the agent's
    cite-by-path workflow."""
    hit = {
        "_id": "z3",
        "_source": {
            "event": {"dataset": "zeek.ssl"},
            "zeek": {
                "ssl": {"server_name": "api.github.com", "ja3": "abc123"},
                "http": {  # not normally on a ssl event but we tolerate
                    "method": "GET",
                    "host": "api.github.com",
                    "uri": "/users",
                    "status_code": 200,
                    "user_agent": "curl/8",
                },
            },
        },
    }
    alert = SoAlert.from_es_hit(hit)
    assert alert.zeek_ssl_server_name == "api.github.com"
    assert alert.zeek_ssl_ja3 == "abc123"
    assert alert.zeek_http_method == "GET"
    assert alert.zeek_http_status == 200


def test_alert_typed_zeek_conn_byte_volumes() -> None:
    """conn orig_bytes/resp_bytes are surfaced so the agent can SEE the
    exfil-asymmetry signal (large outbound, tiny inbound) on the prefetch
    without calling t_query_zeek_logs. Regression: these were dropped,
    blinding the agent to multi-GB outbound transfers."""
    hit = {
        "_id": "zc",
        "_source": {
            "event": {"dataset": "zeek.conn"},
            "zeek": {
                "conn": {
                    "conn_state": "SF",
                    "duration": 32400.0,
                    "orig_bytes": 4200000000,  # 4.2 GB out
                    "resp_bytes": 4100000,  # 4.1 MB in
                }
            },
        },
    }
    alert = SoAlert.from_es_hit(hit)
    assert alert.zeek_conn_orig_bytes == 4200000000
    assert alert.zeek_conn_resp_bytes == 4100000
    # and the field survives the prompt serialization (non-None → kept)
    dump = alert.model_dump(mode="json", exclude_none=True)
    assert dump["zeek_conn_orig_bytes"] == 4200000000


def test_alert_typed_zeek_ja3s_and_file_fields() -> None:
    """ja3s (server TLS fingerprint) + zeek.files MIME/hashes/size are
    surfaced — a PE (application/x-dosexec) over HTTP plus its hash is the
    strongest malware-delivery signal and must reach the prefetch."""
    ssl_hit = {
        "_id": "zs",
        "_source": {
            "event": {"dataset": "zeek.ssl"},
            "zeek": {"ssl": {"ja3": "client123", "ja3s": "server456"}},
        },
    }
    ssl_alert = SoAlert.from_es_hit(ssl_hit)
    assert ssl_alert.zeek_ssl_ja3 == "client123"
    assert ssl_alert.zeek_ssl_ja3s == "server456"

    file_hit = {
        "_id": "zf",
        "_source": {
            "event": {"dataset": "zeek.files"},
            "zeek": {
                "files": {
                    "mime_type": "application/x-dosexec",
                    "md5": "e1adf8f9e7b3a6c5d4b9a8c7e6f5a4b3",
                    "sha256": "deadbeef" * 8,
                    "total_bytes": 3145728,
                }
            },
        },
    }
    file_alert = SoAlert.from_es_hit(file_hit)
    assert file_alert.zeek_files_mime_type == "application/x-dosexec"
    assert file_alert.zeek_files_md5 == "e1adf8f9e7b3a6c5d4b9a8c7e6f5a4b3"
    assert file_alert.zeek_files_sha256 == "deadbeef" * 8
    assert file_alert.zeek_files_total_bytes == 3145728


# ---- ECS-first Zeek extraction on a modern (Elastic-Agent 9.x) grid ----
# The prefetch-drops-payload / synth-recall=0 root cause: modern SO populates
# ECS field names (client.bytes, hash.ja3s, ssl.server_name, dns.query.name,
# http.virtual_host, file.*) and leaves zeek.* mapped-but-empty. The extractor
# must read the ECS names, fall back to zeek.* for legacy SO + synth fixtures,
# and let ECS win when both are present. A 0 byte-count is a real value.


def test_alert_ecs_conn_bytes_resolved_on_modern_grid() -> None:
    """On modern SO conn byte volumes live at client.bytes / server.bytes;
    zeek.conn.*_bytes are empty. The exfil-asymmetry signal must still reach
    the prefetch."""
    hit = {
        "_id": "ecs-conn",
        "_source": {
            "event": {"dataset": "zeek.conn", "duration": 32400.0},
            "client": {"bytes": 4200000000},  # 4.2 GB out
            "server": {"bytes": 4100000},  # 4.1 MB in
            "connection": {"state": "SF", "history": "ShADadFf"},
        },
    }
    alert = SoAlert.from_es_hit(hit)
    assert alert.zeek_conn_orig_bytes == 4200000000
    assert alert.zeek_conn_resp_bytes == 4100000
    assert alert.zeek_conn_state == "SF"
    assert alert.zeek_conn_history == "ShADadFf"
    assert alert.zeek_conn_duration == 32400.0


def test_alert_ecs_zero_byte_count_preserved() -> None:
    """A literal 0 byte-count is a REAL value (e.g. a S0 connection with no
    payload), not 'missing' — first_present must return it, not skip to the
    zeek.* fallback or None."""
    hit = {
        "_id": "ecs-zero",
        "_source": {
            "event": {"dataset": "zeek.conn"},
            "client": {"bytes": 0},
            "server": {"bytes": 0},
        },
    }
    alert = SoAlert.from_es_hit(hit)
    assert alert.zeek_conn_orig_bytes == 0
    assert alert.zeek_conn_resp_bytes == 0
    # and 0 survives prompt serialization with exclude_none (0 is not None)
    dump = alert.model_dump(mode="json", exclude_none=True)
    assert dump["zeek_conn_orig_bytes"] == 0
    assert dump["zeek_conn_resp_bytes"] == 0


def test_alert_ecs_ssl_ja3s_and_sni_resolved_on_modern_grid() -> None:
    """ja3/ja3s live at hash.ja3 / hash.ja3s and SNI at ssl.server_name on
    modern SO; zeek.ssl.* are empty."""
    hit = {
        "_id": "ecs-ssl",
        "_source": {
            "event": {"dataset": "zeek.ssl"},
            "hash": {"ja3": "client123", "ja3s": "server456"},
            "ssl": {"server_name": "api.github.com"},
        },
    }
    alert = SoAlert.from_es_hit(hit)
    assert alert.zeek_ssl_ja3 == "client123"
    assert alert.zeek_ssl_ja3s == "server456"
    assert alert.zeek_ssl_server_name == "api.github.com"


def test_alert_ecs_http_fields_resolved_on_modern_grid() -> None:
    """HTTP host lives at http.virtual_host, UA at user_agent.original, status
    at http.status_code on modern SO."""
    hit = {
        "_id": "ecs-http",
        "_source": {
            "event": {"dataset": "zeek.http"},
            "http": {"method": "POST", "virtual_host": "evil.example", "uri": "/c2"},
            "url": {"path": "/should-not-win"},
            "http.status_code": 200,
            "user_agent": {"original": "Go-http-client/1.1"},
        },
    }
    alert = SoAlert.from_es_hit(hit)
    assert alert.zeek_http_method == "POST"
    assert alert.zeek_http_host == "evil.example"  # http.virtual_host beats url.domain
    assert alert.zeek_http_uri == "/c2"  # http.uri beats url.path
    assert alert.zeek_http_status == 200
    assert alert.zeek_http_user_agent == "Go-http-client/1.1"


def test_alert_ecs_file_fields_resolved_on_modern_grid() -> None:
    """Transferred-file MIME/hashes/size live at file.* on modern SO."""
    hit = {
        "_id": "ecs-file",
        "_source": {
            "event": {"dataset": "zeek.files"},
            "file": {
                "mime_type": "application/x-dosexec",
                "hash": {
                    "md5": "e1adf8f9e7b3a6c5d4b9a8c7e6f5a4b3",
                    "sha256": "deadbeef" * 8,
                },
                "size": 3145728,
            },
        },
    }
    alert = SoAlert.from_es_hit(hit)
    assert alert.zeek_files_mime_type == "application/x-dosexec"
    assert alert.zeek_files_md5 == "e1adf8f9e7b3a6c5d4b9a8c7e6f5a4b3"
    assert alert.zeek_files_sha256 == "deadbeef" * 8
    assert alert.zeek_files_total_bytes == 3145728


def test_alert_ecs_dns_fields_resolved_on_modern_grid() -> None:
    """DNS query/rcode live at dns.query.name / dns.response.code_name on
    modern SO (zeek.dns.* empty). Both the typed zeek_dns_* fields and the
    guarded dns_query/dns_rcode_name path must resolve."""
    hit = {
        "_id": "ecs-dns",
        "_source": {
            "event": {"dataset": "zeek.dns"},
            "dns": {
                "query": {"name": "evil.example"},
                "response": {"code_name": "NXDOMAIN"},
            },
        },
    }
    alert = SoAlert.from_es_hit(hit)
    # typed zeek_dns_* (from _extract_zeek_typed)
    assert alert.zeek_dns_query == "evil.example"
    assert alert.zeek_dns_rcode_name == "NXDOMAIN"
    # guarded dns_query/dns_rcode_name (the is_zeek_dns path)
    assert alert.dns_query == "evil.example"
    assert alert.dns_rcode_name == "NXDOMAIN"


def test_alert_legacy_zeek_fields_still_extracted_via_fallback() -> None:
    """Old SO + the synth eval fixtures write zeek.* names. With NO ECS fields
    present, the extractor must still resolve every field via the zeek.*
    fallback so those keep working."""
    hit = {
        "_id": "legacy",
        "_source": {
            "event": {"dataset": "zeek.conn"},
            "zeek": {
                "conn": {
                    "conn_state": "S0",
                    "history": "S",
                    "duration": 0.123,
                    "orig_bytes": 4200000000,
                    "resp_bytes": 4100000,
                },
                "ssl": {"server_name": "legacy.example", "ja3": "L-c", "ja3s": "L-s"},
                "http": {
                    "method": "GET",
                    "host": "legacy.example",
                    "uri": "/x",
                    "status_code": 404,
                    "user_agent": "curl/7",
                },
                "files": {
                    "mime_type": "application/zip",
                    "md5": "a" * 32,
                    "sha256": "b" * 64,
                    "total_bytes": 99,
                },
                "dns": {"query": ["legacy.example"], "rcode_name": "NOERROR"},
            },
        },
    }
    alert = SoAlert.from_es_hit(hit)
    assert alert.zeek_conn_state == "S0"
    assert alert.zeek_conn_history == "S"
    assert alert.zeek_conn_duration == 0.123
    assert alert.zeek_conn_orig_bytes == 4200000000
    assert alert.zeek_conn_resp_bytes == 4100000
    assert alert.zeek_ssl_server_name == "legacy.example"
    assert alert.zeek_ssl_ja3 == "L-c"
    assert alert.zeek_ssl_ja3s == "L-s"
    assert alert.zeek_http_method == "GET"
    assert alert.zeek_http_host == "legacy.example"
    assert alert.zeek_http_uri == "/x"
    assert alert.zeek_http_status == 404
    assert alert.zeek_http_user_agent == "curl/7"
    assert alert.zeek_files_mime_type == "application/zip"
    assert alert.zeek_files_md5 == "a" * 32
    assert alert.zeek_files_sha256 == "b" * 64
    assert alert.zeek_files_total_bytes == 99
    assert alert.zeek_dns_query == "legacy.example"
    assert alert.zeek_dns_rcode_name == "NOERROR"


def test_alert_legacy_ssl_ja3_hash_fallback_preserved() -> None:
    """The pre-existing zeek.ssl.ja3_hash / ja3s_hash fallback (not in the
    candidate tables) must still resolve when neither ECS nor zeek.ssl.ja3*
    is present — don't regress older ingest layouts."""
    hit = {
        "_id": "legacy-hash",
        "_source": {
            "event": {"dataset": "zeek.ssl"},
            "zeek": {"ssl": {"ja3_hash": "H-c", "ja3s_hash": "H-s"}},
        },
    }
    alert = SoAlert.from_es_hit(hit)
    assert alert.zeek_ssl_ja3 == "H-c"
    assert alert.zeek_ssl_ja3s == "H-s"


def test_alert_ecs_wins_when_both_ecs_and_zeek_present() -> None:
    """When a doc carries BOTH ECS and zeek.* values for the same logical
    field, ECS must win (candidate lists are ECS-first). This is the real-grid
    edge where zeek.* is mapped but stale/empty-ish and ECS is the truth."""
    hit = {
        "_id": "both",
        "_source": {
            "event": {"dataset": "zeek.conn"},
            # ECS truth
            "client": {"bytes": 1000},
            "server": {"bytes": 2000},
            "connection": {"state": "SF", "history": "ShADadFf"},
            "ssl": {"server_name": "ecs.example"},
            "hash": {"ja3": "ecs-ja3", "ja3s": "ecs-ja3s"},
            "http": {"virtual_host": "ecs.example", "method": "POST"},
            "file": {"mime_type": "application/x-dosexec"},
            "dns": {"query": {"name": "ecs.example"}, "response": {"code_name": "NOERROR"}},
            # legacy zeek.* — must lose
            "zeek": {
                "conn": {
                    "orig_bytes": 9,
                    "resp_bytes": 9,
                    "conn_state": "S0",
                    "history": "X",
                },
                "ssl": {"server_name": "zeek.example", "ja3": "z-ja3", "ja3s": "z-ja3s"},
                "http": {"host": "zeek.example", "method": "GET"},
                "files": {"mime_type": "text/plain"},
                "dns": {"query": ["zeek.example"], "rcode_name": "SERVFAIL"},
            },
        },
    }
    alert = SoAlert.from_es_hit(hit)
    assert alert.zeek_conn_orig_bytes == 1000  # client.bytes, not zeek 9
    assert alert.zeek_conn_resp_bytes == 2000  # server.bytes, not zeek 9
    assert alert.zeek_conn_state == "SF"  # connection.state, not zeek S0
    assert alert.zeek_conn_history == "ShADadFf"  # connection.history, not zeek X
    assert alert.zeek_ssl_server_name == "ecs.example"  # ssl.server_name
    assert alert.zeek_ssl_ja3 == "ecs-ja3"  # hash.ja3
    assert alert.zeek_ssl_ja3s == "ecs-ja3s"  # hash.ja3s
    assert alert.zeek_http_host == "ecs.example"  # http.virtual_host
    assert alert.zeek_http_method == "POST"  # http.method
    assert alert.zeek_files_mime_type == "application/x-dosexec"  # file.mime_type
    assert alert.zeek_dns_query == "ecs.example"  # dns.query.name
    assert alert.zeek_dns_rcode_name == "NOERROR"  # dns.response.code_name


def test_alert_zeek_typed_fields_skipped_for_non_zeek_dataset() -> None:
    """Suricata alerts shouldn't have zeek_* fields populated even if
    the source happens to carry a `zeek` block (defensive against
    schema drift / weird ingestion)."""
    hit = {
        "_id": "x",
        "_source": {
            "event": {"dataset": "suricata.alert"},
            "zeek": {"conn": {"conn_state": "S0"}},
        },
    }
    alert = SoAlert.from_es_hit(hit)
    assert alert.zeek_conn_state is None


def test_alert_prefetch_parse_errors_records_drift() -> None:
    """When typed extraction hits a type mismatch (schema drift), the
    field stays None AND a short note appears in `prefetch_parse_errors`
    so the agent knows to fall back to `raw`."""
    hit = {
        "_id": "z4",
        "_source": {
            "event": {"dataset": "zeek.conn"},
            "zeek": {"conn": {"duration": "not-a-number"}},
        },
    }
    alert = SoAlert.from_es_hit(hit)
    assert alert.zeek_conn_duration is None
    # The parse-error note is now keyed by the LOGICAL field name (the value can
    # come from event.duration on modern SO or zeek.conn.duration on legacy),
    # not a single ES path.
    assert any("conn.duration" in e for e in alert.prefetch_parse_errors)


def test_alert_message_parse_failure_recorded() -> None:
    """A `message` blob that's a non-empty string but invalid JSON
    surfaces as `prefetch_parse_errors` so the agent knows the typed
    fields couldn't be derived from message JSON."""
    hit = {"_id": "x", "_source": {"message": "not json {"}}
    alert = SoAlert.from_es_hit(hit)
    assert alert.message == "not json {"
    assert any("message" in e for e in alert.prefetch_parse_errors)


def test_alert_parses_alert_action_from_message_json() -> None:
    """Suricata writes alert.action inside the `message` JSON string.
    Pull it out so the agent can see whether the detection was
    `allowed` or `blocked`."""
    msg = (
        '{"timestamp":"2026-05-07T19:32:29Z","event_type":"alert",'
        '"alert":{"action":"allowed","gid":1,"signature_id":2048555}}'
    )
    hit = {
        "_id": "x",
        "_source": {
            "message": msg,
            "event": {"action": "blocked"},
        },
    }
    alert = SoAlert.from_es_hit(hit)
    # Both fields populated independently (different sources).
    assert alert.alert_action == "allowed"  # from message JSON
    assert alert.event_action == "blocked"  # from ECS top-level


def test_alert_handles_malformed_message_json() -> None:
    """A malformed `message` blob must not abort alert parsing; the typed
    fields just stay None."""
    hit = {
        "_id": "x",
        "_source": {"message": "not json {{"},
    }
    alert = SoAlert.from_es_hit(hit)
    assert alert.alert_action is None
    assert alert.message == "not json {{"  # raw still preserved


def test_alert_parses_classtype_from_message_json() -> None:
    """Suricata writes the classtype as `alert.category` inside message JSON.
    The classifier (issue #18) uses this as the strongest routing signal."""
    msg = (
        '{"timestamp":"2026-05-10T12:00:00Z","event_type":"alert",'
        '"alert":{"category":"trojan-activity","signature_id":2048555}}'
    )
    hit = {"_id": "x", "_source": {"message": msg}}
    alert = SoAlert.from_es_hit(hit)
    assert alert.classtype == "trojan-activity"


def test_alert_classtype_none_when_missing() -> None:
    """Alerts without an `alert.category` in message JSON keep `classtype=None`."""
    hit = {"_id": "x", "_source": {}}
    alert = SoAlert.from_es_hit(hit)
    assert alert.classtype is None


def test_alert_event_module_dataset_category() -> None:
    """ECS event.module / dataset / category are routing keys for batch
    eval queries and for the fast-path classifier (issue #13)."""
    hit = {
        "_id": "x",
        "_source": {
            "event": {
                "module": "suricata",
                "dataset": "suricata.alert",
                "category": ["network"],
            },
        },
    }
    alert = SoAlert.from_es_hit(hit)
    assert alert.event_module == "suricata"
    assert alert.event_dataset == "suricata.alert"
    assert alert.event_category == "network"


# ---- SoCase ------------------------------------------------------------


def test_case_from_so_doc(sample_case: dict[str, Any]) -> None:
    case = SoCase.from_so_doc(sample_case)
    assert case.id == "case-001"
    assert case.title == "Investigate suspicious outbound traffic"
    assert case.status == "in progress"
    assert case.severity == "high"
    assert case.assignee_id == "user-bob"
    assert case.created == datetime(2026, 5, 7, 11, 0, 0, tzinfo=UTC)
    assert case.updated == datetime(2026, 5, 7, 11, 30, 0, tzinfo=UTC)
    assert "malware" in case.tags
    assert case.raw == sample_case


def test_case_with_minimal_doc() -> None:
    doc = {"id": "case-min"}
    case = SoCase.from_so_doc(doc)
    assert case.id == "case-min"
    assert case.title == ""
    assert case.status == "unknown"
    assert case.tags == []


# ---- SoDetection -------------------------------------------------------


def test_detection_from_so_doc(sample_detection: dict[str, Any]) -> None:
    det = SoDetection.from_so_doc(sample_detection)
    assert det.id == "det-001"
    assert det.engine == "suricata"
    assert det.is_enabled is True
    assert det.severity == "high"
    assert "malware" in det.tags


def test_detection_isenabled_defaults_true_when_missing() -> None:
    det = SoDetection.from_so_doc({"id": "det-x", "title": "x"})
    assert det.is_enabled is True


# ---- SoPlaybook --------------------------------------------------------


def test_playbook_from_so_doc(sample_playbook: dict[str, Any]) -> None:
    pb = SoPlaybook.from_so_doc(sample_playbook)
    assert pb.id == "pb-001"
    assert len(pb.questions) == 3
    assert pb.questions[0].question.startswith("Is the destination IP")
    assert pb.questions[0].is_required is True
    assert pb.questions[2].is_required is False


def test_playbook_handles_no_questions() -> None:
    pb = SoPlaybook.from_so_doc({"id": "pb-x", "title": "empty"})
    assert pb.questions == []


# ---- _parse_iso — C5: naive timestamps forced to UTC -------------------


def test_parse_iso_naive_becomes_utc() -> None:
    """Naive timestamp (no Z/offset) is treated as UTC (C5 fix)."""
    result = _parse_iso("2026-05-07T10:30:00")
    assert result is not None
    assert result.tzinfo == UTC
    assert result.year == 2026
    assert result.hour == 10


def test_parse_iso_z_suffix_is_utc() -> None:
    """Trailing Z is still accepted and produces UTC-aware datetime."""
    result = _parse_iso("2026-05-07T10:30:00Z")
    assert result is not None
    assert result.tzinfo is not None
    assert result.utcoffset().total_seconds() == 0  # type: ignore[union-attr]


def test_parse_iso_offset_preserved() -> None:
    """Explicit +HH:MM offset is preserved, not overwritten."""
    result = _parse_iso("2026-05-07T10:30:00+05:00")
    assert result is not None
    assert result.utcoffset().total_seconds() == 5 * 3600  # type: ignore[union-attr]


def test_parse_iso_none_returns_none() -> None:
    assert _parse_iso(None) is None


def test_parse_iso_datetime_passthrough_naive_gets_utc() -> None:
    """A naive datetime object passed in also gets UTC forced."""
    naive = datetime(2026, 6, 1, 12, 0, 0)
    result = _parse_iso(naive)
    assert result is not None
    assert result.tzinfo == UTC


# ---- ECS array-vs-scalar (Elastic Defend endpoint telemetry) -----------
#
# Elasticsearch has no array type: every field may hold zero, one or many
# values, and ECS says so explicitly. A model annotation admitting only a
# scalar is therefore stricter than the data it parses, and on the measured
# grids the strictness bites hardest on endpoint telemetry: every
# `endpoint.events.*` document Elastic Defend writes carries `event.action` as
# a list.


def _endpoint_process_hit() -> dict[str, Any]:
    """One Elastic Defend process document, in the shape the grid stores it.

    `event.action`, `event.type` and `event.category` are lists because Defend
    writes them that way, not because anything unusual happened here.
    """
    return {
        "_id": "endpoint-process-1",
        "_source": {
            "@timestamp": "2026-09-05T03:56:37.665117Z",
            "agent": {"type": "endpoint"},
            "message": "Endpoint process event",
            "tags": ["elastic-agent", "events.process"],
            "data_stream": {
                "type": "logs",
                "namespace": "default",
                "dataset": "endpoint.events.process",
            },
            "host": {"name": "ws-01", "ip": ["198.51.100.20"]},
            "user": {"name": "svc-build"},
            "process": {"entity_id": "yG4ttygujemL", "name": "powershell.exe"},
            "event": {
                "kind": "event",
                "module": "endpoint",
                "dataset": "endpoint.events.process",
                "action": ["start", "end"],
                "category": ["process"],
                "type": ["start", "end"],
            },
        },
    }


def test_alert_reads_event_action_when_endpoint_telemetry_writes_a_list() -> None:
    """The reported defect. `SoAlert.event_action` was `str | None`, so every
    Elastic Defend document failed validation outright and the whole alert was
    unreadable: a promotion anchored on endpoint telemetry died in prefetch
    before it fetched a single pivot.

    First element, matching how the neighbouring `event.category` has always
    been read.
    """
    alert = SoAlert.from_es_hit(_endpoint_process_hit())
    assert alert.event_action == "start"
    assert alert.event_category == "process"
    assert alert.id == "endpoint-process-1"
    # The full list stays reachable: nothing is lost, only narrowed.
    assert get_dotted(alert.raw, "event.action") == ["start", "end"]


def test_alert_event_action_scalar_is_still_read_as_itself() -> None:
    """Negative control for the unwrap: a document writing the scalar (every
    Suricata alert on both measured grids) must be unaffected."""
    hit = {"_id": "x", "_source": {"event": {"action": "blocked", "dataset": "suricata.alert"}}}
    alert = SoAlert.from_es_hit(hit)
    assert alert.event_action == "blocked"


def _wrap_every_leaf(node: Any) -> Any:
    """Rewrite a document so every scalar leaf is a single-element list.

    A field that is already a list is left alone: Elasticsearch flattens
    nested arrays, so `[["a"]]` is not a shape any grid can produce.
    """
    if isinstance(node, dict):
        return {k: _wrap_every_leaf(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_wrap_every_leaf(v) if isinstance(v, dict) else v for v in node]
    return [node]


def test_alert_parses_a_document_whose_every_leaf_is_a_list() -> None:
    """The structural guard, rather than a list of fields.

    Enumerating the fields that "can" be arrays is a losing game: Elasticsearch
    permits an array anywhere, so the next scalar attribute someone adds is the
    next outage. This wraps every leaf of a realistic Suricata document and
    asserts the model still parses it, which fails the moment a new scalar
    field is read without unwrapping.
    """
    source = {
        "@timestamp": "2026-09-05T12:00:00Z",
        "event": {
            "action": "allowed",
            "module": "suricata",
            "dataset": "suricata.alert",
            "category": "intrusion_detection",
            "severity": 1,
            "severity_label": "high",
        },
        "rule": {"name": "ET EXPLOIT something", "uuid": "abc-123"},
        "source": {"ip": "198.51.100.9", "port": 44_301},
        "destination": {"ip": "198.51.100.20", "port": 8080},
        "host": {"name": "sensor-a", "ip": ["198.51.100.3"]},
        "user": {"name": "svc-build"},
        "process": {"entity_id": "pid-1"},
        "file": {"hash": {"sha256": "a" * 64}},
        "network": {"community_id": "1:abcdef"},
        "payload_printable": "GET / HTTP/1.1",
        "tags": ["alert"],
    }
    alert = SoAlert.from_es_hit({"_id": "wrapped", "_source": _wrap_every_leaf(source)})
    assert alert.event_action == "allowed"
    assert alert.rule_name == "ET EXPLOIT something"
    assert alert.source_ip == "198.51.100.9"
    assert alert.destination_port == 8080
    assert alert.severity_score == 1
    assert alert.host_ip == ["198.51.100.3"]
    assert alert.file_hash_sha256 == "a" * 64


def test_alert_parses_a_zeek_document_whose_every_leaf_is_a_list() -> None:
    """Same guard over the Zeek branch, which reads through the candidate
    tables in `fields.py` rather than through `get_dotted` directly."""
    source = {
        "@timestamp": "2026-09-05T12:00:00Z",
        "event": {"dataset": "zeek.conn", "duration": 12.5},
        "connection": {"state": "SF", "history": "ShADad"},
        "client": {"bytes": 4_200},
        "server": {"bytes": 91},
        "network": {"protocol": "ssl"},
        "ssl": {"server_name": "example.test", "established": True},
        "hash": {"ja3": "b" * 32, "ja3s": "c" * 32},
        "file": {"mime_type": "application/x-dosexec", "size": 1024},
        "http": {
            "method": "GET",
            "virtual_host": "example.test",
            "uri": "/x",
            "status_code": 200,
        },
        "user_agent": {"original": "curl/8.5.0"},
        "ssh": {"auth_success": False, "auth_attempts": 3, "client": "SSH-2.0-OpenSSH"},
    }
    alert = SoAlert.from_es_hit({"_id": "zeek-wrapped", "_source": _wrap_every_leaf(source)})
    assert alert.zeek_conn_state == "SF"
    assert alert.zeek_conn_orig_bytes == 4_200
    assert alert.zeek_conn_duration == 12.5
    assert alert.zeek_ssl_server_name == "example.test"
    assert alert.zeek_files_mime_type == "application/x-dosexec"
    assert alert.zeek_http_status == 200
    assert alert.zeek_ssh_auth_attempts == 3
    # A list-wrapped False is False. `bool([False])` is True, so an unwrap that
    # skipped the booleans would report a FAILED SSH login as a successful one.
    assert alert.zeek_ssh_auth_success is False
    assert alert.zeek_ssl_established is True
    assert alert.prefetch_parse_errors == []


def test_alert_tags_written_as_a_scalar_do_not_explode_into_characters() -> None:
    """The same asymmetry inverted. `tags` is annotated `list[str]` and built
    with `list(...)`, so a grid writing the scalar produced one tag per
    character. Both measured grids hold documents in each shape."""
    hit = {"_id": "x", "_source": {"tags": "alert"}}
    assert SoAlert.from_es_hit(hit).tags == ["alert"]


def test_case_and_detection_read_scalars_out_of_list_wrapped_documents() -> None:
    """`SoCase` and `SoDetection` are read from `so-case*` / `so-detection*`
    index documents, so they carry the same Elasticsearch guarantee as the
    events index: none."""
    case = SoCase.from_so_doc(
        {"id": ["c-1"], "title": ["Suspicious login"], "status": ["open"], "tags": "triage"}
    )
    assert case.id == "c-1"
    assert case.title == "Suspicious login"
    assert case.status == "open"
    assert case.tags == ["triage"]

    det = SoDetection.from_so_doc(
        {"id": ["d-1"], "title": ["Rule"], "author": ["ann", "bob"], "tags": "sigma"}
    )
    assert det.id == "d-1"
    assert det.author == "ann"
    assert det.tags == ["sigma"]


# ---- The `event_data` envelope (Sigma and host detections) --------------
#
# Security Onion's Sigma pipeline does not merge the endpoint document it
# matched into the alert. It writes the detection's own identity at the top
# level (rule.*, event.module/dataset/severity, @timestamp) and nests the WHOLE
# originating document under `event_data`. Reading only the top level returned
# null for every pivot the investigator needs, on exactly the detection class
# that has no flow to fall back on.


def _sigma_envelope_hit() -> dict[str, Any]:
    """A Sigma detection in the shape Security Onion writes it.

    Modelled on a live grid document: the detection identity is top-level, the
    matched event is nested whole under `event_data`.
    """
    return {
        "_id": "sigma-1",
        "_source": {
            "@timestamp": "2026-09-07T13:02:04.000Z",
            "rule": {
                "name": "Grid Node Login Failure (SSH)",
                "uuid": "923421c7-9b1e-45d4-80cc-e21d060c8723",
                "product": "linux",
            },
            "event": {
                "module": "sigma",
                "dataset": "sigma.alert",
                "severity": 4,
                "severity_label": "high",
            },
            "sigma_level": "high",
            "tags": "alert",
            "event_data": {
                "@timestamp": "2026-09-07T13:00:14Z",
                "source": {"ip": "192.0.2.77", "port": 47108},
                "destination": {"ip": "198.51.100.10", "port": 22},
                "host": {"name": "grid-node-01", "ip": ["198.51.100.10", "fe80::1"]},
                "user": {"name": "svc-backup"},
                "process": {"name": "sshd-session", "entity_id": "proc-9"},
                "network": {"community_id": "1:envelope=="},
                "file": {"hash": {"sha256": "deadbeef" * 8}},
                "event": {
                    "module": "system",
                    "dataset": "system.auth",
                    "action": "ssh_login",
                    "category": ["authentication"],
                    "outcome": "failure",
                },
                "message": "Invalid user svc-backup from 192.0.2.77 port 47108",
                "tags": ["elastic-agent", "input-syslog"],
            },
        },
    }


def test_alert_reads_every_pivot_out_of_the_event_data_envelope() -> None:
    """The reported defect: all six named pivots, plus the four found beside
    them, came back null on a nested detection while severity was populated."""
    alert = SoAlert.from_es_hit(_sigma_envelope_hit())
    assert alert.source_ip == "192.0.2.77"
    assert alert.source_port == 47108
    assert alert.destination_ip == "198.51.100.10"
    assert alert.destination_port == 22
    assert alert.host_name == "grid-node-01"
    assert alert.host_ip == ["198.51.100.10", "fe80::1"]
    assert alert.user_name == "svc-backup"
    assert alert.process_entity_id == "proc-9"
    assert alert.file_hash_sha256 == "deadbeef" * 8
    assert alert.network_community_id == "1:envelope=="
    assert alert.event_action == "ssh_login"
    assert alert.event_category == "authentication"
    assert alert.message == "Invalid user svc-backup from 192.0.2.77 port 47108"


def test_alert_keeps_the_detections_own_identity_when_the_envelope_disagrees() -> None:
    """Precedence. The two levels genuinely disagree about `event.module` and
    `event.dataset`: the top level names the SIGMA detection, the envelope names
    the log the rule fired on. Letting the envelope win would relabel every
    Sigma alert as `system.auth` and break every reader that routes on it."""
    alert = SoAlert.from_es_hit(_sigma_envelope_hit())
    assert alert.event_module == "sigma"
    assert alert.event_dataset == "sigma.alert"
    assert alert.rule_name == "Grid Node Login Failure (SSH)"
    assert alert.severity_label == "high"
    assert alert.severity_score == 4
    assert alert.tags == ["alert"]
    assert alert.timestamp == datetime(2026, 9, 7, 13, 2, 4, tzinfo=UTC)


def test_alert_reads_the_envelope_in_the_flat_dotted_layout_too() -> None:
    """The envelope is subject to the same flat-vs-nested drift as everything
    else on an ES document."""
    hit = {
        "_id": "sigma-flat",
        "_source": {
            "rule.name": "Weak Encryption Enabled and Kerberoast",
            "event.dataset": "sigma.alert",
            "event_data.source.ip": "192.0.2.9",
            "event_data.host.name": "dc-01",
            "event_data.user.name": "svc-sql",
        },
    }
    alert = SoAlert.from_es_hit(hit)
    assert alert.source_ip == "192.0.2.9"
    assert alert.host_name == "dc-01"
    assert alert.user_name == "svc-sql"
    assert alert.event_dataset == "sigma.alert"


def test_alert_with_top_level_fields_ignores_a_contradicting_envelope() -> None:
    """NEGATIVE CONTROL. An alert that genuinely carries top-level fields must
    be read exactly as before, envelope or no envelope. Every pivot below is
    present at BOTH levels with different values; the top level wins on all."""
    hit = {
        "_id": "both-levels",
        "_source": {
            "source": {"ip": "192.0.2.1", "port": 1111},
            "destination": {"ip": "192.0.2.2", "port": 2222},
            "host": {"name": "top-host", "ip": ["192.0.2.1"]},
            "user": {"name": "top-user"},
            "process": {"entity_id": "top-proc"},
            "file": {"hash": {"sha256": "aa" * 32}},
            "network": {"community_id": "1:top=="},
            "event": {"action": "blocked", "category": "network", "dataset": "suricata.alert"},
            "message": "top-level message",
            "event_data": {
                "source": {"ip": "198.51.100.1", "port": 3333},
                "destination": {"ip": "198.51.100.2", "port": 4444},
                "host": {"name": "nested-host", "ip": ["198.51.100.1"]},
                "user": {"name": "nested-user"},
                "process": {"entity_id": "nested-proc"},
                "file": {"hash": {"sha256": "bb" * 32}},
                "network": {"community_id": "1:nested=="},
                "event": {"action": "allowed", "category": "authentication"},
                "message": "nested message",
            },
        },
    }
    alert = SoAlert.from_es_hit(hit)
    assert alert.source_ip == "192.0.2.1"
    assert alert.source_port == 1111
    assert alert.destination_ip == "192.0.2.2"
    assert alert.destination_port == 2222
    assert alert.host_name == "top-host"
    assert alert.host_ip == ["192.0.2.1"]
    assert alert.user_name == "top-user"
    assert alert.process_entity_id == "top-proc"
    assert alert.file_hash_sha256 == "aa" * 32
    assert alert.network_community_id == "1:top=="
    assert alert.event_action == "blocked"
    assert alert.event_category == "network"
    assert alert.message == "top-level message"


def test_an_envelope_changes_nothing_on_an_alert_that_carries_its_own_fields(
    sample_alert: dict[str, Any],
) -> None:
    """NEGATIVE CONTROL, the ~99% path, stated over the whole model.

    A real Suricata alert is parsed twice: once as the grid stores it, and once
    with a contradicting envelope bolted on. Every field the document answers
    for itself must read the same in both. The envelope may only fill a field
    the top level left empty, and never move one it had already answered.
    """
    plain = SoAlert.from_es_hit(sample_alert)
    with_envelope = {
        "_id": sample_alert["_id"],
        "_source": {
            **sample_alert["_source"],
            "event_data": {
                "source": {"ip": "198.51.100.1", "port": 3333},
                "destination": {"ip": "198.51.100.2", "port": 4444},
                "host": {"name": "nested-host", "ip": ["198.51.100.1"]},
                "user": {"name": "nested-user"},
                "process": {"entity_id": "nested-proc"},
                "file": {"hash": {"sha256": "bb" * 32}},
                "network": {"community_id": "1:nested=="},
                "event": {"action": "allowed", "category": "authentication"},
                "message": "nested message",
                "tags": ["nested"],
            },
        },
    }
    wrapped = SoAlert.from_es_hit(with_envelope)
    before, after = plain.model_dump(), wrapped.model_dump()
    moved = {k: (before[k], after[k]) for k in before if before[k] != after[k]}
    # `event.action` / `event.category` are absent from this document, so the
    # envelope is allowed to answer them. Nothing else may differ, and nothing
    # the document DID answer may have moved.
    assert set(moved) == {"event_action", "event_category"}
    assert all(old in (None, [], "") for old, _ in moved.values())
    # And the values really are the top-level ones, not a coincidence of nulls.
    assert plain.source_ip == "192.168.1.50"
    assert plain.destination_ip == "203.0.113.10"
    assert plain.host_name == "workstation-01"
    assert plain.user_name == "alice"
    assert plain.process_entity_id == "proc-abc-123"
    assert plain.tags == ["alert", "suricata", "malware"]


def test_alert_unwraps_a_zeek_document_carried_inside_an_envelope() -> None:
    """A Sigma rule that fires on Zeek telemetry nests a Zeek document. The
    typed-Zeek extraction is gated on the dataset, so it has to consult the
    envelope's dataset as well as the top-level one, or the whole typed block
    stays None on exactly the documents it was written for."""
    hit = {
        "_id": "sigma-zeek",
        "_source": {
            "rule": {"name": "Long Connection to Rare Destination"},
            "event": {"module": "sigma", "dataset": "sigma.alert", "severity_label": "high"},
            "event_data": {
                "source": {"ip": "192.0.2.30"},
                "destination": {"ip": "203.0.113.9"},
                "event": {"dataset": "zeek.conn", "duration": 3600.5},
                "connection": {"state": "SF", "history": "ShAdDaf"},
                "client": {"bytes": 4200000000},
                "server": {"bytes": 4100000},
            },
        },
    }
    alert = SoAlert.from_es_hit(hit)
    # The model still reports the DETECTION's dataset.
    assert alert.event_dataset == "sigma.alert"
    assert alert.zeek_conn_state == "SF"
    assert alert.zeek_conn_history == "ShAdDaf"
    assert alert.zeek_conn_duration == 3600.5
    assert alert.zeek_conn_orig_bytes == 4200000000
    assert alert.zeek_conn_resp_bytes == 4100000


def test_alert_reads_the_suricata_message_json_out_of_an_envelope() -> None:
    """`classtype` and `payload_printable` are parsed out of the `message` JSON
    string, so a nested `message` took them down with it."""
    hit = {
        "_id": "sigma-suri",
        "_source": {
            "rule": {"name": "Sigma over a Suricata alert"},
            "event": {"module": "sigma", "dataset": "sigma.alert"},
            "event_data": {
                "message": (
                    '{"alert": {"category": "trojan-activity", "action": "allowed"},'
                    ' "payload_printable": "GET /gate.php HTTP/1.1"}'
                ),
            },
        },
    }
    alert = SoAlert.from_es_hit(hit)
    assert alert.classtype == "trojan-activity"
    assert alert.alert_action == "allowed"
    assert alert.payload_printable == "GET /gate.php HTTP/1.1"
