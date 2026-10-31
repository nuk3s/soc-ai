"""The Event timeline view model (change D).

The page reads only the documents a run already stores: the enriched alert
context, the hits of every tool result, and the source a t_get_event_raw call
returned. Every time here is relative to now. Every address is TEST-NET and
every uid is synthetic.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from soc_ai.api.webui import _event_timeline
from soc_ai.api.webui._event_timeline import (
    hunt_event_timeline,
    investigation_event_timeline,
)

RUN = "01JAB3C4D5E6F7G8H9J0K1M2N4"


def _base() -> datetime:
    return (datetime.now(UTC) - timedelta(days=5)).replace(microsecond=0)


def _z(at: datetime) -> str:
    return at.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _ev(kind: str, payload: Any, seq: int = 0) -> SimpleNamespace:
    return SimpleNamespace(kind=kind, payload=payload, sequence=seq, investigation_id=RUN)


def _cite(target: str, resolved: bool | None = True, kind: str = "id") -> SimpleNamespace:
    return SimpleNamespace(text=target, kind=kind, target=target, resolved=resolved)


def _soalert(doc_id: str, at: datetime, **fields: Any) -> dict[str, Any]:
    return {"id": doc_id, "timestamp": at.isoformat(), **fields}


def test_subject_documents_read_oldest_first_with_two_waves() -> None:
    base = _base()
    exploit = base + timedelta(hours=22, minutes=27)
    docs = [
        _soalert(
            "subjectFiles0001",
            exploit + timedelta(minutes=1),
            event_dataset="zeek.files",
            zeek_files_mime_type="text/x-php",
            source_ip="198.51.100.20",
            destination_ip="192.0.2.11",
        ),
        *[
            _soalert(
                f"subjectAlert000{i}",
                exploit + timedelta(seconds=10 * i),
                event_dataset="suricata.alert",
                rule_name=f"ET EXPLOIT Example upload attempt {i}",
                source_ip="192.0.2.11",
                destination_ip="198.51.100.20",
                destination_port=80,
            )
            for i in (3, 2, 1)
        ],
        _soalert(
            "subjectSsh000001",
            base + timedelta(minutes=5),
            event_dataset="zeek.ssh",
            zeek_ssh_auth_success=True,
            source_ip="192.0.2.10",
            destination_ip="198.51.100.20",
            destination_port=22,
        ),
        _soalert(
            "subjectConn00001",
            base,
            event_dataset="zeek.conn",
            source_ip="192.0.2.10",
            source_port=50111,
            destination_ip="198.51.100.20",
            destination_port=22,
            zeek_conn_state="SF",
            zeek_conn_duration=3000.0,
            zeek_uid="CExampleConnUid1",
        ),
    ]
    events = [
        _ev(
            "enriched_alert_context",
            {
                # The anchor of a hunt-subject run is one of its documents.
                "alert": docs[-1],
                "subject": "hunt",
                "subject_documents": docs,
            },
        )
    ]

    out = investigation_event_timeline(events, [], "complete")

    assert out is not None
    assert out.basis == "hunt_subject"
    ids = [e.id for e in out.entries]
    assert ids[:2] == ["subjectConn00001", "subjectSsh000001"]
    assert ids[2:5] == ["subjectAlert0001", "subjectAlert0002", "subjectAlert0003"]
    assert ids[5] == "subjectFiles0001"
    assert len(out.waves) == 2
    assert out.waves[0].start == _z(base)
    assert out.waves[0].end == _z(base + timedelta(minutes=50))
    assert out.waves[0].documents == 2
    assert out.waves[0].sources == ["192.0.2.10"]
    assert out.waves[1].start == _z(exploit + timedelta(seconds=10))
    conn = out.entries[0]
    assert conn.end == _z(base + timedelta(minutes=50))
    assert conn.source == "192.0.2.10:50111"
    assert conn.destination == "198.51.100.20:22"
    assert conn.label == "Connection, state SF"
    assert out.entries[1].label == "SSH login succeeded"
    assert [e.wave for e in out.entries] == [1, 1, 2, 2, 2, 2]
    assert not any(e.cited for e in out.entries)
    assert out.gapMinutes == 30
    assert out.untimed == 0
    assert out.omitted == 0


def _finding_run_docs(base: datetime) -> dict[str, dict[str, Any]]:
    """Two documents of the judged finding, one document of another finding
    that the verdict cites, and one document of another finding that it does
    not cite, days later and between other hosts."""
    return {
        "own_http": _soalert(
            "findingOwnHttp01",
            base,
            event_dataset="zeek.http",
            source_ip="192.0.2.11",
            destination_ip="198.51.100.20",
            destination_port=80,
        ),
        "own_alert": _soalert(
            "findingOwnAlrt01",
            base + timedelta(minutes=5),
            event_dataset="suricata.alert",
            rule_name="ET EXPLOIT Example probe",
            source_ip="192.0.2.11",
            destination_ip="198.51.100.20",
            destination_port=80,
        ),
        "cited_other": _soalert(
            "otherCitedConn01",
            base + timedelta(minutes=10),
            event_dataset="zeek.conn",
            source_ip="192.0.2.11",
            destination_ip="198.51.100.20",
            destination_port=8443,
        ),
        "other": _soalert(
            "otherFindingSsh1",
            base + timedelta(hours=40),
            event_dataset="zeek.ssh",
            source_ip="192.0.2.30",
            destination_ip="203.0.113.9",
            destination_port=22,
        ),
    }


def test_a_finding_run_lists_its_own_documents_and_what_the_verdict_cites() -> None:
    """Prod, 2026-10-30. A run judged the finding "Automated web exploitation
    against blue server". Its Event timeline also listed, as wave 6, an SSH
    session that another finding of the hunt cited. A run that judges one
    finding lists the documents of that finding and the documents that its
    verdict cites. The other findings stay out."""
    docs = _finding_run_docs(_base())
    events = [
        _ev(
            "enriched_alert_context",
            {
                "alert": docs["own_http"],
                "subject": "hunt",
                "subject_documents": [
                    docs["other"],
                    docs["cited_other"],
                    docs["own_alert"],
                    docs["own_http"],
                ],
            },
        )
    ]

    out = investigation_event_timeline(
        events,
        [_cite("otherCitedConn01")],
        "complete",
        focus_ids=["findingOwnHttp01", "findingOwnAlrt01", "t_query_events_oql:zeek.http groupby"],
    )

    assert out is not None
    assert out.basis == "finding"
    assert [e.id for e in out.entries] == [
        "findingOwnHttp01",
        "findingOwnAlrt01",
        "otherCitedConn01",
    ]
    assert len(out.waves) == 1
    assert [e.id for e in out.entries if e.cited] == ["otherCitedConn01"]


def test_a_finding_whose_citations_hold_no_stored_document_lists_the_anchor() -> None:
    """A finding that cites only tool calls has no document of its own. The
    list then holds the anchor of the run and the documents that the verdict
    cites, and still no document of another finding."""
    docs = _finding_run_docs(_base())
    events = [
        _ev(
            "enriched_alert_context",
            {
                "alert": docs["own_http"],
                "subject": "hunt",
                "subject_documents": [docs["other"], docs["own_http"]],
            },
        )
    ]

    out = investigation_event_timeline(
        events,
        [_cite("otherCitedConn01")],
        "complete",
        focus_ids=["t_host_summary:192.0.2.11"],
    )

    # The cited document is not stored, so only the anchor has a time.
    assert out is None

    events.append(
        _ev(
            "tool_result",
            {
                "tool_name": "t_query_events_oql",
                "result": {
                    "hits": [
                        {
                            "_id": "otherCitedConn01",
                            "_source": {
                                "@timestamp": docs["cited_other"]["timestamp"],
                                "event": {"dataset": "zeek.conn"},
                                "source": {"ip": "192.0.2.11"},
                                "destination": {"ip": "198.51.100.20", "port": 8443},
                            },
                        }
                    ]
                },
            },
            seq=1,
        )
    )
    out = investigation_event_timeline(
        events, [_cite("otherCitedConn01")], "complete", focus_ids=["t_host_summary:192.0.2.11"]
    )
    assert out is not None
    assert out.basis == "finding"
    assert [e.id for e in out.entries] == ["findingOwnHttp01", "otherCitedConn01"]


def test_a_cited_uid_resolves_through_an_oql_hit() -> None:
    base = _base()
    at = base + timedelta(hours=2)
    events = [
        _ev(
            "enriched_alert_context",
            {"alert": _soalert("alertDocument001", base, event_dataset="suricata.alert")},
        ),
        _ev("tool_call", {"tool_name": "t_query_events_oql", "args": {}, "tool_call_id": "c1"}),
        _ev(
            "tool_result",
            {
                "tool_name": "t_query_events_oql",
                "tool_call_id": "c1",
                "result": {
                    "total": 1,
                    "hits": [
                        {
                            "_id": "esDocHttp0000001",
                            "_source": {
                                "@timestamp": _z(at),
                                "event": {"dataset": "zeek.http"},
                                "log": {"id": {"uid": "CExampleUid00001"}},
                            },
                        }
                    ],
                },
            },
        ),
    ]

    out = investigation_event_timeline(events, [_cite("CExampleUid00001")], "complete")

    assert out is not None
    assert out.basis == "alert"
    http = [e for e in out.entries if e.dataset == "zeek.http"]
    assert len(http) == 1
    assert http[0].at == _z(at)
    assert http[0].cited is True
    assert http[0].id == "esDocHttp0000001"
    alert = [e for e in out.entries if e.id == "alertDocument001"]
    assert alert and alert[0].cited is False


@pytest.mark.parametrize("form", ["dict", "json", "targeted"])
def test_a_get_event_raw_result_resolves_by_its_call_argument(form: str) -> None:
    base = _base()
    at = base + timedelta(hours=3, seconds=7)
    source = {"@timestamp": _z(at), "event": {"dataset": "zeek.dns"}, "dns": {"query_name": "x"}}
    if form == "targeted":
        tool_events = [
            _ev(
                "targeted_dispatch",
                {"tool_name": "t_get_event_raw", "tool_args": {"event_id": "rawDocument00001"}},
            ),
            _ev("targeted_tool_result", {"tool_name": "t_get_event_raw", "result": source}),
        ]
    else:
        args: Any = {"event_id": "rawDocument00001"}
        if form == "json":
            args = json.dumps(args)
        tool_events = [
            _ev("tool_call", {"tool_name": "t_get_event_raw", "args": args, "tool_call_id": "r1"}),
            _ev(
                "tool_result",
                {"tool_name": "t_get_event_raw", "result": source, "tool_call_id": "r1"},
            ),
        ]
    events = [
        _ev("enriched_alert_context", {"alert": _soalert("alertDocument001", base)}),
        *tool_events,
    ]

    out = investigation_event_timeline(events, [_cite("rawDocument00001")], "complete")

    assert out is not None
    raw = [e for e in out.entries if e.id == "rawDocument00001"]
    assert len(raw) == 1
    assert raw[0].at == _z(at)
    assert raw[0].dataset == "zeek.dns"
    assert raw[0].cited is True


def test_untimed_counts_only_real_cited_documents() -> None:
    base = _base()
    events = [
        _ev("enriched_alert_context", {"alert": _soalert("alertDocument001", base)}),
        _ev(
            "tool_result",
            {
                "tool_name": "t_beacon_profile",
                "tool_call_id": "b1",
                "result": {"sample_ids": ["sampleNoSource01"]},
            },
        ),
        _ev(
            "tool_result",
            {
                "tool_name": "t_query_events_oql",
                "tool_call_id": "q1",
                "result": {
                    "hits": [
                        {
                            "_id": "timedDocument001",
                            "_source": {"@timestamp": _z(base + timedelta(minutes=3))},
                        },
                        {
                            "_id": "refusedDocument1",
                            "_source": {"@timestamp": _z(base + timedelta(minutes=4))},
                        },
                    ]
                },
            },
        ),
    ]
    citations = [
        _cite("sampleNoSource01"),
        _cite("timedDocument001"),
        _cite("refusedDocument1", resolved=False),
        _cite("alert.rule_name", kind="path"),
    ]

    out = investigation_event_timeline(events, citations, "complete")

    assert out is not None
    assert out.untimed == 1
    assert [e.id for e in out.entries] == ["alertDocument001", "timedDocument001"]

    findings = [
        {
            "title": "Upload",
            "citations": [
                "01JAB3C4D5E6F7G8H9J0K1M2N3",
                "t_rule_prevalence",
                "alert.rule_name",
                "timedDocument001",
                "alertDocument001",
            ],
        }
    ]
    hunt_events = [
        _ev(
            "tool_result",
            {
                "tool_name": "t_query_events_oql",
                "tool_call_id": "q1",
                "result": {
                    "hits": [
                        {"_id": "timedDocument001", "_source": {"@timestamp": _z(base)}},
                        {
                            "_id": "alertDocument001",
                            "_source": {"@timestamp": _z(base + timedelta(hours=1))},
                        },
                    ]
                },
            },
        )
    ]
    hunt = hunt_event_timeline(hunt_events, findings, "complete")
    assert hunt is not None
    assert hunt.basis == "hunt"
    assert hunt.untimed == 0
    assert [e.id for e in hunt.entries] == ["timedDocument001", "alertDocument001"]


def test_a_hash_a_cve_or_a_rule_uuid_is_not_an_untimed_document() -> None:
    """A verdict and a finding can cite a file hash, a CVE id or a rule UUID.
    They are evidence ids, not grid documents, so the page does not count them
    as documents with no stored time. A grid document whose _id has a hash
    shape still shows when the run stored it."""
    base = _base()
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    cve = "CVE-2026-109618"
    rule_uuid = "5f4c3b2a-1d0e-4f9a-8b7c-6d5e4f3a2b1c"
    stored_hash_id = "a" * 40
    events = [
        _ev("enriched_alert_context", {"alert": _soalert("alertDocument001", base)}),
        _ev(
            "tool_result",
            {
                "tool_name": "t_query_events_oql",
                "tool_call_id": "q1",
                "result": {
                    "hits": [
                        {
                            "_id": "timedDocument001",
                            "_source": {"@timestamp": _z(base + timedelta(minutes=3))},
                        },
                        {
                            "_id": stored_hash_id,
                            "_source": {"@timestamp": _z(base + timedelta(minutes=5))},
                        },
                    ]
                },
            },
        ),
    ]
    citations = [
        _cite("timedDocument001"),
        _cite(sha256),
        _cite(md5),
        _cite(cve),
        _cite(rule_uuid),
        _cite(stored_hash_id),
        _cite("missingDocument1"),
    ]

    out = investigation_event_timeline(events, citations, "complete")

    assert out is not None
    assert out.untimed == 1
    assert [e.id for e in out.entries] == [
        "alertDocument001",
        "timedDocument001",
        stored_hash_id,
    ]

    findings = [
        {
            "title": "Dropper",
            "citations": [sha256, cve, rule_uuid, "timedDocument001", stored_hash_id],
        }
    ]
    hunt = hunt_event_timeline(events[1:], findings, "complete")
    assert hunt is not None
    assert hunt.untimed == 0
    assert [e.id for e in hunt.entries] == ["timedDocument001", stored_hash_id]


def test_a_bad_document_never_fails_the_timeline(caplog: pytest.LogCaptureFixture) -> None:
    base = _base()
    naive = (base + timedelta(hours=1)).replace(tzinfo=None).isoformat()
    events = [
        _ev("enriched_alert_context", "not a dict"),
        _ev("enriched_alert_context", {"alert": _soalert("alertDocument001", base)}),
        _ev(
            "tool_result",
            {
                "tool_call_id": "q1",
                "result": {
                    "hits": [
                        {"_id": "naiveDocument001", "_source": {"@timestamp": naive}},
                        {"_id": 5, "_source": "x"},
                        {"_id": "badSourceDoc0001", "_source": "x"},
                    ]
                },
            },
        ),
    ]
    citations = [_cite("naiveDocument001"), _cite("badSourceDoc0001")]

    out = investigation_event_timeline(events, citations, "complete")

    assert out is not None
    naive_entry = [e for e in out.entries if e.id == "naiveDocument001"]
    assert naive_entry[0].at == _z(base + timedelta(hours=1))
    assert out.untimed == 1

    def boom(*_a: Any, **_k: Any) -> None:
        raise RuntimeError("forced")

    original = _event_timeline._build_investigation
    _event_timeline._build_investigation = boom  # type: ignore[assignment]
    try:
        with caplog.at_level(logging.WARNING, logger="soc_ai.api.webui._event_timeline"):
            assert investigation_event_timeline(events, citations, "complete") is None
    finally:
        _event_timeline._build_investigation = original
    lines = [r for r in caplog.records if "could not build the event timeline" in r.getMessage()]
    assert len(lines) == 1
    assert RUN in lines[0].getMessage()


def test_a_running_run_has_no_event_timeline() -> None:
    base = _base()
    events = [
        _ev(
            "enriched_alert_context",
            {
                "alert": _soalert("alertDocument001", base),
                "subject_documents": [
                    _soalert("subjectDocument1", base),
                    _soalert("subjectDocument2", base + timedelta(hours=2)),
                ],
            },
        )
    ]
    assert investigation_event_timeline(events, [], "running") is None
    assert investigation_event_timeline(events, [], "queued") is None
    assert investigation_event_timeline(events, [], "complete") is not None

    # The same hunt events and findings for every status, so only the status
    # guard can return None. A hunt that investigates its findings already
    # holds its final findings, so its page gets the section.
    hunt_events = [
        _ev(
            "tool_result",
            {
                "tool_name": "t_query_events_oql",
                "tool_call_id": "q1",
                "result": {
                    "hits": [
                        {"_id": "huntDocument0001", "_source": {"@timestamp": _z(base)}},
                        {
                            "_id": "huntDocument0002",
                            "_source": {"@timestamp": _z(base + timedelta(hours=2))},
                        },
                    ]
                },
            },
        )
    ]
    findings = [{"title": "Two", "citations": ["huntDocument0001", "huntDocument0002"]}]
    assert hunt_event_timeline(hunt_events, findings, "running") is None
    assert hunt_event_timeline(hunt_events, findings, "queued") is None
    for status in ("investigating", "complete"):
        hunt = hunt_event_timeline(hunt_events, findings, status)
        assert hunt is not None, status
        assert [e.id for e in hunt.entries] == ["huntDocument0001", "huntDocument0002"]


def test_a_label_reads_scrubbed() -> None:
    base = _base()
    events = [
        _ev(
            "enriched_alert_context",
            {
                "alert": _soalert("alertDocument001", base),
                "subject_documents": [
                    _soalert("subjectDocument1", base),
                    _soalert(
                        "subjectDocument2",
                        base + timedelta(minutes=2),
                        event_dataset="zeek.http",
                        zeek_http_method="GET",
                        zeek_http_uri="/login?user=admin&password=hunter2xyz",
                    ),
                ],
            },
        )
    ]
    out = investigation_event_timeline(events, [], "complete")
    assert out is not None
    label = out.entries[1].label
    assert "hunter2xyz" not in label
    assert label.startswith("GET /login?user=admin&password=")
