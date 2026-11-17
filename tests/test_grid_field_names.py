"""Each field name that the code or the primer uses must be a name the grid holds.

Measured defect (production review 2026-11-12, hunts finding 2). The field
table listed ``ssh.auth_success`` and ``zeek.ssh.auth_success``. The primer
taught ``zeek.ssh.auth_success:true``. A Security Onion 3.x grid holds the
value in ``ssh.authentication.success``. Ten of twelve scheduled hunts
filtered on the dead name, got zero, and six reports stated "no successful SSH
login" while the grid held successful logins. The same table feeds the
"completed SSH login" evidence of alert triage, so that line could not fire.

The class is larger than SSH. ``tests/fixtures/grid_field_census.json`` holds
the field names of the stored documents of one production grid. These tests
check every field table and every primer example against it.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.agent.evidence import _pivot_decisive_evidence
from soc_ai.config import Settings
from soc_ai.errors import OqlValidationError
from soc_ai.event_time import document_label
from soc_ai.so_client import fields
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.models import SoAlert
from soc_ai.so_client.oql import (
    GroupBy,
    SortBy,
    collect_filter_fields,
    parse_oql,
    validate_oql,
)
from soc_ai.tools.query_events import query_events_oql
from soc_ai.tools.query_zeek import _build_source_projection, _coalesce_source, query_zeek_logs

_REPO = Path(__file__).resolve().parents[1]
_CENSUS: dict[str, list[str]] = json.loads(
    (_REPO / "tests" / "fixtures" / "grid_field_census.json").read_text(encoding="utf-8")
)["datasets"]


def _holds(dataset: str, name: str) -> bool:
    """True when a stored document of ``dataset`` holds ``name`` or a field below it."""
    return any(held == name or held.startswith(name + ".") for held in _CENSUS[dataset])


def _live(dataset: str, candidates: tuple[str, ...]) -> list[str]:
    return [name for name in candidates if _holds(dataset, name)]


def _make_elastic(settings: Settings, response: dict[str, Any]) -> tuple[ElasticClient, AsyncMock]:
    fake_es = AsyncMock()
    fake_es.search.return_value = response
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        client = ElasticClient(settings)
    return client, fake_es


def _grid_ssh_hit(success: Any, attempts: int = 2) -> dict[str, Any]:
    """A zeek.ssh document in the shape that a Security Onion 3.x grid stores."""
    return {
        "_id": "ssh-1",
        "_source": {
            "@timestamp": "2026-11-07T02:20:52.000Z",
            "event": {"dataset": "zeek.ssh", "module": "zeek", "category": "network"},
            "source": {"ip": "192.0.2.58", "port": 41144},
            "destination": {"ip": "192.0.2.75", "port": 22},
            "ssh": {
                "authentication": {"success": success, "attempts": attempts},
                "client": "SSH-2.0-OpenSSH_10.2",
                "server": "SSH-2.0-OpenSSH_10.0p2 Debian-7",
                "version": 2,
                "direction": "INBOUND",
            },
        },
    }


# ---------------------------------------------------------------------------
# The SSH login fields: every read site
# ---------------------------------------------------------------------------


def test_ssh_login_of_a_grid_document_reaches_the_typed_alert() -> None:
    alert = SoAlert.from_es_hit(_grid_ssh_hit(True))
    assert alert.zeek_ssh_auth_success is True
    assert alert.zeek_ssh_auth_attempts == 2
    assert alert.zeek_ssh_client == "SSH-2.0-OpenSSH_10.2"


def test_ssh_login_of_a_grid_document_gives_the_triage_evidence_line() -> None:
    alert = SoAlert.from_es_hit(_grid_ssh_hit(True))
    bullets = " ".join(_pivot_decisive_evidence(alert, "ssh-1"))
    assert "completed SSH login" in bullets
    assert "in 2 attempt(s)" in bullets


def test_failed_ssh_login_of_a_grid_document_gives_no_evidence_line() -> None:
    """Negative control: the new name must not turn a failed login into a login."""
    alert = SoAlert.from_es_hit(_grid_ssh_hit(False, attempts=6))
    assert alert.zeek_ssh_auth_success is False
    assert "completed SSH login" not in " ".join(_pivot_decisive_evidence(alert, "ssh-1"))


def test_ssh_document_with_no_login_result_stays_unknown() -> None:
    """Negative control: a document with no result is not a failed login."""
    hit = _grid_ssh_hit(True)
    del hit["_source"]["ssh"]["authentication"]
    alert = SoAlert.from_es_hit(hit)
    assert alert.zeek_ssh_auth_success is None
    assert "completed SSH login" not in " ".join(_pivot_decisive_evidence(alert, "ssh-1"))


def test_ssh_login_of_a_grid_document_labels_the_timeline_row() -> None:
    alert = SoAlert.from_es_hit(_grid_ssh_hit(True))
    assert document_label(alert.model_dump(mode="json")) == "SSH login succeeded"


def test_zeek_pivot_projects_and_returns_the_grid_ssh_names() -> None:
    projection = _build_source_projection()
    assert "ssh.authentication.success" in projection
    assert "ssh.authentication.attempts" in projection
    row = _coalesce_source(_grid_ssh_hit(True)["_source"])
    assert row["zeek.ssh.auth_success"] is True
    assert row["zeek.ssh.auth_attempts"] == 2
    assert row["zeek.ssh.client"] == "SSH-2.0-OpenSSH_10.2"


@pytest.mark.asyncio
async def test_zeek_pivot_asks_for_the_file_log_under_both_dataset_names(
    settings_kratos: Settings,
) -> None:
    elastic, fake_es = _make_elastic(settings_kratos, {"took": 0, "hits": {"total": 0, "hits": []}})
    await query_zeek_logs("1:abc123==", elastic=elastic, settings=settings_kratos)
    must = fake_es.search.call_args.kwargs["body"]["query"]["bool"]["must"]
    datasets = next(c["terms"]["event.dataset"] for c in must if "terms" in c)
    assert "zeek.file" in datasets and "zeek.files" in datasets
    assert "zeek.ssh" in datasets


# ---------------------------------------------------------------------------
# The class: every field table against the census
# ---------------------------------------------------------------------------

# (table name, the dataset whose stored documents must hold one of its names).
_TABLE_DATASETS: tuple[tuple[str, str], ...] = (
    ("DNS_QUERY", "zeek.dns"),
    ("DNS_RESOLVED_IP", "zeek.dns"),
    ("DNS_REGISTERED_DOMAIN", "zeek.dns"),
    ("DNS_TOP_LEVEL_DOMAIN", "zeek.dns"),
    ("DNS_RCODE", "zeek.dns"),
    ("DNS_QTYPE", "zeek.dns"),
    ("CONN_ORIG_BYTES", "zeek.conn"),
    ("CONN_RESP_BYTES", "zeek.conn"),
    ("CONN_TOTAL_BYTES", "zeek.conn"),
    ("CONN_RESP_PACKETS", "zeek.conn"),
    # The probe rules read these. With no live name they would judge nothing.
    ("RESPONDER_COUNTERS", "zeek.conn"),
    ("CONN_DURATION", "zeek.conn"),
    ("CONN_STATE", "zeek.conn"),
    ("CONN_HISTORY", "zeek.conn"),
    ("CONN_SERVICE", "zeek.conn"),
    ("CONN_TRANSPORT", "zeek.conn"),
    ("CONN_LOCAL_ORIG", "zeek.conn"),
    ("CONN_LOCAL_RESP", "zeek.conn"),
    ("SSL_JA3", "zeek.ssl"),
    ("SSL_JA3S", "zeek.ssl"),
    ("SSL_SNI", "zeek.ssl"),
    ("SSL_VERSION", "zeek.ssl"),
    ("SSL_ESTABLISHED", "zeek.ssl"),
    ("HTTP_HOST", "zeek.http"),
    ("HTTP_METHOD", "zeek.http"),
    ("HTTP_URI", "zeek.http"),
    ("HTTP_STATUS", "zeek.http"),
    ("HTTP_USER_AGENT", "zeek.http"),
    ("FILE_MIME", "zeek.file"),
    ("FILE_MD5", "zeek.file"),
    ("FILE_SIZE", "zeek.file"),
    ("FILE_NAME", "zeek.file"),
    ("KERBEROS_CIPHER", "zeek.kerberos"),
    ("KERBEROS_SERVICE", "zeek.kerberos"),
    ("KERBEROS_CLIENT", "zeek.kerberos"),
    ("KERBEROS_REQUEST_TYPE", "zeek.kerberos"),
    ("KERBEROS_SUCCESS", "zeek.kerberos"),
    ("SMB_MAPPING_SHARE_TYPE", "zeek.smb_mapping"),
    ("SMB_MAPPING_PATH", "zeek.smb_mapping"),
    ("DCE_RPC_ENDPOINT", "zeek.dce_rpc"),
    ("DCE_RPC_OPERATION", "zeek.dce_rpc"),
    ("SSH_AUTH_SUCCESS", "zeek.ssh"),
    ("SSH_AUTH_ATTEMPTS", "zeek.ssh"),
    ("SSH_CLIENT", "zeek.ssh"),
    ("SSH_SERVER", "zeek.ssh"),
    ("SSH_VERSION", "zeek.ssh"),
    ("SSH_DIRECTION", "zeek.ssh"),
    ("DHCP_HOSTNAME", "zeek.dhcp"),
    ("DHCP_DOMAIN", "zeek.dhcp"),
    ("DHCP_MAC", "zeek.dhcp"),
    ("DHCP_ASSIGNED_IP", "zeek.dhcp"),
    ("DHCP_CLIENT_ADDRESS", "zeek.dhcp"),
    ("HOST_MAC", "zeek.dhcp"),
    ("SOFTWARE_NAME", "zeek.software"),
    ("SOFTWARE_VERSION", "zeek.software"),
    ("SOFTWARE_TYPE", "zeek.software"),
)

# Tables with no grid name in the census. The stored documents hold no document
# of the dataset, or no document of the dataset holds the value. A census that
# gains the dataset must move the table to _TABLE_DATASETS.
_NOT_IN_CENSUS: frozenset[str] = frozenset(
    {
        "FILE_SHA256",  # zeek.file holds hash.md5 and hash.sha1 only
        "KERBEROS_REALM",  # the realm is inside kerberos.client
        "DHCP_CLIENT_FQDN",
        "SMB_FILE_ACTION",  # no zeek.smb_files document
        "SMB_FILE_NAME",
        "SMB_FILE_PATH",
        "SMB_MAPPING_SERVICE",  # the mapping documents hold smb.path only
        "SMB_HOST_NAME",
        "NTLM_HOSTNAME",  # no zeek.ntlm document
        "NTLM_DOMAIN",
        "NTLM_SERVER_NB",
        "BEACON_PROFILE",  # summary documents exist only as synth fixtures
        "DNS_TUNNEL_PROFILE",
    }
)

# Tuples in fields.py that are not a table of names for one value.
_NOT_A_FIELD_TABLE: frozenset[str] = frozenset(
    {
        "DATASET_IDENTITY",
        "DATASET_NAME_FIELDS",
        "FLOW_DATASETS",
        "ZEEK_FILE_DATASETS",
        "NETWORK_SENSOR_DATASET_PREFIXES",
        "HOST_OWN_ADDRESSES",
        "LOCAL_END_FIELDS",
        "LOGICAL_FIELDS",
        "CONN_REFUSED_STATES",  # values of connection.state
    }
)


def _field_tables() -> dict[str, tuple[str, ...]]:
    return {
        name: value
        for name, value in vars(fields).items()
        if name.isupper()
        and not name.startswith("_")
        and isinstance(value, tuple)
        and value
        and all(isinstance(item, str) for item in value)
        and name not in _NOT_A_FIELD_TABLE
    }


@pytest.mark.parametrize(("table", "dataset"), _TABLE_DATASETS)
def test_field_table_holds_a_name_that_the_grid_stores(table: str, dataset: str) -> None:
    candidates = getattr(fields, table)
    assert _live(dataset, candidates), (
        f"no stored {dataset} document holds a name of fields.{table}: {candidates}"
    )


def test_every_field_table_is_checked_or_listed_as_not_in_the_census() -> None:
    """A new table cannot skip the check."""
    checked = {table for table, _dataset in _TABLE_DATASETS}
    assert checked.isdisjoint(_NOT_IN_CENSUS)
    assert set(_field_tables()) == checked | _NOT_IN_CENSUS


def test_the_census_check_fails_for_the_names_that_caused_the_defect() -> None:
    """Negative control: the check must refuse the table as it was before the fix."""
    assert _live("zeek.ssh", ("ssh.auth_success", "zeek.ssh.auth_success")) == []
    assert _live("zeek.http", ("user_agent.original", "http.user_agent")) == []
    assert _live("zeek.file", ("file.hash.md5", "zeek.files.md5")) == []
    assert _live("zeek.kerberos", ("kerberos.cipher", "zeek.kerberos.cipher")) == []
    assert _live("zeek.software", ("software.unparsed_version",)) == []


def test_no_zeek_dataset_of_the_census_holds_a_zeek_prefixed_field() -> None:
    """The reason the primer must not teach ``zeek.<log>.<field>``."""
    for dataset, names in _CENSUS.items():
        assert not [name for name in names if name.startswith("zeek.")], dataset


# ---------------------------------------------------------------------------
# The class: every primer example against the census
# ---------------------------------------------------------------------------

_OQL_BLOCK = re.compile(r"```oql\n(.*?)```", re.DOTALL)
_DOCS = ("docs/OQL_PRIMER.md", "docs/OQL_HUNT_EXAMPLES.md")


def _examples() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for doc in _DOCS:
        text = (_REPO / doc).read_text(encoding="utf-8")
        out.extend((doc, " ".join(block.split())) for block in _OQL_BLOCK.findall(text))
    return out


def _example_fields(query: str) -> set[str]:
    ast = parse_oql(query.replace("<name>", "placeholder"))
    validate_oql(ast)
    names = collect_filter_fields(ast.filter_)
    for stage in ast.pipes:
        if isinstance(stage, GroupBy):
            names.update(stage.fields)
        elif isinstance(stage, SortBy) and stage.field != "count":
            names.add(stage.field)
    return names


def _example_datasets(query: str) -> list[str]:
    return re.findall(r"event\.dataset:([a-z_.]+)", query)


def test_the_docs_hold_oql_examples() -> None:
    assert len(_examples()) >= 20


@pytest.mark.parametrize(("doc", "query"), _examples())
def test_primer_example_names_no_zeek_prefixed_field(doc: str, query: str) -> None:
    """A current grid holds no value under ``zeek.<log>.<field>``."""
    dead = sorted(name for name in _example_fields(query) if name.startswith("zeek."))
    assert not dead, f"{doc}: {query!r} filters or groups on {dead}"


@pytest.mark.parametrize(("doc", "query"), _examples())
def test_primer_example_names_only_fields_that_its_dataset_stores(doc: str, query: str) -> None:
    """An example that names one census dataset uses only names that dataset holds."""
    datasets = [name for name in _example_datasets(query) if name in _CENSUS]
    if len(datasets) != 1 or len(_example_datasets(query)) != 1:
        pytest.skip("the example does not name exactly one census dataset")
    absent = sorted(name for name in _example_fields(query) if not _holds(datasets[0], name))
    assert not absent, f"{doc}: no stored {datasets[0]} document holds {absent} ({query!r})"


@pytest.mark.parametrize(("doc", "query"), _examples())
def test_primer_example_names_only_fields_that_the_grid_stores(doc: str, query: str) -> None:
    """Each field of each example is in a stored document of some census dataset."""
    absent = sorted(
        name
        for name in _example_fields(query)
        if not any(_holds(dataset, name) for dataset in _CENSUS)
    )
    assert not absent, f"{doc}: no stored document holds {absent} ({query!r})"


def test_the_primer_check_fails_for_the_examples_that_caused_the_defect() -> None:
    """Negative control: the two checks must refuse the examples as they were."""
    old_ssh = "event.dataset:zeek.ssh AND zeek.ssh.auth_success:true"
    assert [n for n in _example_fields(old_ssh) if n.startswith("zeek.")]
    old_outbound = "event.dataset:zeek.conn AND network.direction:outbound | groupby destination.ip"
    assert [n for n in _example_fields(old_outbound) if not _holds("zeek.conn", n)] == [
        "network.direction"
    ]
    old_nxdomain = "event.dataset:zeek.dns AND dns.response.code_name:NXDOMAIN | groupby host.name"
    assert [n for n in _example_fields(old_nxdomain) if not _holds("zeek.dns", n)] == ["host.name"]


def test_primer_teaches_the_grid_name_of_the_ssh_login_field() -> None:
    primer = (_REPO / "docs" / "OQL_PRIMER.md").read_text(encoding="utf-8")
    assert "event.dataset:zeek.ssh AND ssh.authentication.success:true" in primer
    assert "zeek.ssh.auth_success:true" not in primer


def test_the_validator_accepts_the_grid_names_of_the_protocol_logs() -> None:
    """The validator refused kerberos, smb and dce_rpc and accepted their dead zeek names."""
    for query in (
        "event.dataset:zeek.kerberos AND kerberos.request_type:TGS",
        "event.dataset:zeek.kerberos AND kerberos.ticket.cipher:rc4-hmac",
        "event.dataset:zeek.smb_mapping | groupby smb.path",
        "event.dataset:zeek.dce_rpc AND dce_rpc.operation:DRSGetNCChanges",
        "event.dataset:zeek.ssh AND ssh.authentication.success:true",
    ):
        validate_oql(parse_oql(query))


# ---------------------------------------------------------------------------
# A filter on one name of a field matches every name of that field
# ---------------------------------------------------------------------------


async def _issued_query(settings: Settings, oql: str) -> dict[str, Any]:
    elastic, fake_es = _make_elastic(settings, {"took": 1, "hits": {"total": 0, "hits": []}})
    await query_events_oql(oql, elastic=elastic, settings=settings)
    must = fake_es.search.call_args_list[0].kwargs["body"]["query"]["bool"]["must"]
    assert len(must) == 1
    return must[0]  # type: ignore[no-any-return]


def _terms(clause: dict[str, Any]) -> list[dict[str, Any]]:
    """Every term clause at any depth."""
    found: list[dict[str, Any]] = []
    stack: list[Any] = [clause]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if "term" in node:
                found.append(node["term"])
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return found


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "written",
    ["zeek.ssh.auth_success", "ssh.auth_success", "ssh.authentication.success"],
)
async def test_filter_on_one_ssh_name_matches_every_ssh_name(
    settings_kratos: Settings, written: str
) -> None:
    query = await _issued_query(settings_kratos, f"event.dataset:zeek.ssh AND {written}:true")
    terms = _terms(query)
    for name in fields.SSH_AUTH_SUCCESS:
        assert {name: "true"} in terms
    assert {"event.dataset": "zeek.ssh"} in terms
    # The three names are alternatives. A document needs one of them.
    widened = next(
        c
        for c in query["bool"]["must"]
        if "ssh.authentication.success" in json.dumps(c.get("bool", {}).get("should", []))
    )
    assert widened["bool"]["minimum_should_match"] == 1
    assert len(widened["bool"]["should"]) == len(fields.SSH_AUTH_SUCCESS)


@pytest.mark.asyncio
async def test_filter_on_a_field_outside_the_tables_is_unchanged(
    settings_kratos: Settings,
) -> None:
    """Negative control: only a name in a table widens."""
    query = await _issued_query(settings_kratos, "source.ip:192.0.2.7 AND destination.port:22")
    assert query == {
        "bool": {
            "must": [{"term": {"source.ip": "192.0.2.7"}}, {"term": {"destination.port": "22"}}]
        }
    }


@pytest.mark.asyncio
async def test_negated_filter_excludes_every_name(settings_kratos: Settings) -> None:
    """Negative control: NOT over a widened term must not become a match."""
    query = await _issued_query(settings_kratos, "NOT zeek.ssh.auth_success:true")
    inner = query["bool"]["must_not"][0]
    assert {name for term in _terms(inner) for name in term} == set(fields.SSH_AUTH_SUCCESS)
    assert inner["bool"]["minimum_should_match"] == 1


@pytest.mark.asyncio
async def test_host_fields_of_the_dhcp_tables_do_not_widen(settings_kratos: Settings) -> None:
    """Negative control: host.hostname names the shipper on most documents."""
    query = await _issued_query(settings_kratos, "host.hostname:web01")
    assert query == {"term": {"host.hostname": "web01"}}
    assert fields.same_value_names("host.mac") == ("host.mac",)
    assert fields.same_value_names("client.address") == ("client.address",)


@pytest.mark.asyncio
async def test_file_dataset_filter_matches_both_names(settings_kratos: Settings) -> None:
    query = await _issued_query(settings_kratos, "event.dataset:zeek.files")
    assert {"event.dataset": "zeek.file"} in _terms(query)
    assert {"event.dataset": "zeek.files"} in _terms(query)


@pytest.mark.asyncio
@pytest.mark.parametrize("written", ["tags:alert", "event.kind:alert"])
async def test_alert_filter_matches_both_alert_labels(
    settings_kratos: Settings, written: str
) -> None:
    """Suricata and Sigma alerts hold tags:alert. Endpoint alerts hold event.kind:alert."""
    query = await _issued_query(settings_kratos, written)
    assert {"tags": "alert"} in _terms(query)
    assert {"event.kind": "alert"} in _terms(query)


@pytest.mark.asyncio
async def test_other_event_kind_value_is_unchanged(settings_kratos: Settings) -> None:
    """Negative control: only the alert label widens."""
    query = await _issued_query(settings_kratos, "event.kind:event")
    assert query == {"term": {"event.kind": "event"}}


def test_no_name_is_in_two_tables() -> None:
    """A name in two tables would widen to the names of the wrong value."""
    seen: dict[str, tuple[str, ...]] = {}
    for table in fields.LOGICAL_FIELDS:
        for name in table:
            assert name not in seen, f"{name} is in two tables"
            seen[name] = table


# ---------------------------------------------------------------------------
# Review of 2026-11-13: defects 2, 5, 6, 7 and 11
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("stored", "expected"),
    [
        (True, True),
        ("true", True),
        ("T", True),
        ("1", True),
        (["true"], True),
        (False, False),
        ("false", False),
        ("F", False),
        ("0", False),
        (["false"], False),
        ("maybe", None),
        ("", None),
        ([], None),
        ({"value": True}, None),
        (2, None),
    ],
)
def test_the_ssh_login_result_is_parsed_strictly(stored: Any, expected: bool | None) -> None:
    """A stored "false" is a failed login. Truthiness read it as a completed login."""
    alert = SoAlert.from_es_hit(_grid_ssh_hit(stored, attempts=6))
    assert alert.zeek_ssh_auth_success is expected
    line = " ".join(_pivot_decisive_evidence(alert, "ssh-1"))
    assert ("completed SSH login" in line) is (expected is True)
    label = document_label(alert.model_dump(mode="json"))
    assert (
        label
        == {True: "SSH login succeeded", False: "SSH login failed", None: "SSH session"}[expected]
    )


def test_an_ssh_document_with_attempts_and_no_result_is_unknown() -> None:
    """Six of 140 sampled production documents hold {"attempts": 0} and no result."""
    hit = _grid_ssh_hit(True, attempts=0)
    del hit["_source"]["ssh"]["authentication"]["success"]
    alert = SoAlert.from_es_hit(hit)
    assert alert.zeek_ssh_auth_success is None
    assert alert.zeek_ssh_auth_attempts == 0
    assert "completed SSH login" not in " ".join(_pivot_decisive_evidence(alert, "ssh-1"))


@pytest.mark.parametrize(
    ("field", "attribute"),
    [("ssl.established", "zeek_ssl_established"), ("zeek.dns.rejected", "zeek_dns_rejected")],
)
def test_the_other_stored_flags_are_parsed_strictly(field: str, attribute: str) -> None:
    """The same class: a stored "false" must not read as true."""

    def _alert(value: Any) -> SoAlert:
        return SoAlert.from_es_hit(
            {
                "_id": "x",
                "_source": {
                    "@timestamp": "2026-11-07T02:20:52.000Z",
                    "event": {"dataset": "zeek.ssl", "module": "zeek"},
                    field: value,
                },
            }
        )

    assert getattr(_alert("false"), attribute) is False
    assert getattr(_alert("T"), attribute) is True
    assert getattr(_alert("maybe"), attribute) is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("oql", "positive", "negative"),
    [
        ("tags:alert AND NOT event.kind:alert", {"tags": "alert"}, {"event.kind": "alert"}),
        ("event.kind:alert AND NOT tags:alert", {"event.kind": "alert"}, {"tags": "alert"}),
        (
            "ssh.authentication.success:true AND NOT zeek.ssh.auth_success:true",
            {"ssh.authentication.success": "true"},
            {"zeek.ssh.auth_success": "true"},
        ),
    ],
)
async def test_a_filter_that_names_two_names_of_one_thing_stays_as_written(
    settings_kratos: Settings, oql: str, positive: dict[str, str], negative: dict[str, str]
) -> None:
    """The widening made X AND NOT X from a filter that a document can match."""
    query = await _issued_query(settings_kratos, oql)
    assert query == {
        "bool": {"must": [{"term": positive}, {"bool": {"must_not": [{"term": negative}]}}]}
    }


@pytest.mark.asyncio
async def test_two_names_of_one_dataset_stay_apart(settings_kratos: Settings) -> None:
    """The file log has two names. A filter that names both keeps each value on its side."""
    query = await _issued_query(
        settings_kratos, "event.dataset:zeek.file AND NOT event.dataset:zeek.files"
    )
    positive, negative = query["bool"]["must"]
    assert "zeek.files" not in json.dumps(positive)
    assert {t["event.dataset"] for t in _terms(negative) if "event.dataset" in t} == {"zeek.files"}


@pytest.mark.asyncio
async def test_a_dataset_filter_reads_both_dataset_name_fields(settings_kratos: Settings) -> None:
    """A data stream can name its dataset in data_stream.dataset only."""
    query = await _issued_query(settings_kratos, "event.dataset:network_traffic.dns")
    assert {"event.dataset": "network_traffic.dns"} in _terms(query)
    assert {"data_stream.dataset": "network_traffic.dns"} in _terms(query)


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["cdn.evil.example", "192.0.2.*", '"mail server"'])
async def test_a_value_that_is_not_an_address_does_not_reach_the_address_field(
    settings_kratos: Settings, value: str
) -> None:
    """dns.resolved_ip is ip-typed. Elasticsearch refuses a name or a wildcard on it."""
    query = await _issued_query(settings_kratos, f"zeek.dns.answers:{value}")
    assert "dns.resolved_ip" not in json.dumps(query)
    assert "zeek.dns.answers" in json.dumps(query)


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["192.0.2.7", "192.0.2.0/24", "2001:db8::7"])
async def test_an_address_still_reaches_the_address_field(
    settings_kratos: Settings, value: str
) -> None:
    """Negative control: the type test must not stop the widening of an address."""
    query = await _issued_query(settings_kratos, f'zeek.dns.answers:"{value}"')
    assert {"dns.resolved_ip": value} in _terms(query)
    assert {"zeek.dns.answers": value} in _terms(query)


def test_the_ntlm_names_stay_off_the_whitelist_while_no_stored_document_holds_them() -> None:
    """The census holds no zeek.ntlm document, so the validator still refuses the root."""
    assert not any(name.startswith("ntlm.") for names in _CENSUS.values() for name in names)
    with pytest.raises(OqlValidationError):
        validate_oql(parse_oql("event.dataset:zeek.ntlm | groupby ntlm.hostname"))


# --- the Sigma dry run evaluates the literal rule ---------------------------


def _sigma_draft(oql: str) -> Any:
    from soc_ai.detection.models import SigmaDraft

    return SigmaDraft(
        title="Completed SSH login",
        sigma_yaml=(
            "title: Completed SSH login\nlogsource:\n  category: ssh\ndetection:\n"
            "  selection:\n    x: y\n  condition: selection\n"
        ),
        oql=oql,
        rationale="A completed SSH login from an external address to an internal host.",
        schema_ok=True,
    )


class _GridProbe:
    """A grid that answers the exists probe of each name, and zero for each search."""

    def __init__(self, live: set[str]) -> None:
        self.live = live
        self.searches: list[dict[str, Any]] = []

    async def search(self, index: str, query: dict[str, Any], **kwargs: Any) -> Any:
        from soc_ai.so_client.elastic import EsSearchResult

        if set(query) == {"exists"}:
            return EsSearchResult(total=int(query["exists"]["field"] in self.live), took_ms=1)
        self.searches.append(query)
        return EsSearchResult(total=0, took_ms=1)


@pytest.mark.asyncio
async def test_the_sigma_dry_run_sends_the_rule_as_written_and_names_the_grid_field(
    settings_kratos: Settings,
) -> None:
    """A rewritten dry run reported hits for a rule that Security Onion can never fire."""
    from soc_ai.detection.validators import dry_run_detection

    fields._clear_agg_field_cache()
    grid = _GridProbe({"ssh.authentication.success"})
    draft = _sigma_draft("event.dataset:zeek.ssh AND zeek.ssh.auth_success:true")
    out = await dry_run_detection(draft, elastic=grid, settings=settings_kratos)  # type: ignore[arg-type]
    sent = grid.searches[0]
    assert "ssh.authentication.success" not in json.dumps(sent)
    assert {"zeek.ssh.auth_success": "true"} in _terms(sent)
    assert out.dry_run is not None and out.dry_run.ran is True
    assert out.schema_ok is False
    note = out.validator_note or ""
    assert "`zeek.ssh.auth_success`" in note
    assert "This grid stores the value in `ssh.authentication.success`." in note


@pytest.mark.asyncio
async def test_the_sigma_dry_run_accepts_the_grid_name(settings_kratos: Settings) -> None:
    """Negative control: a draft on the grid name gets no note."""
    from soc_ai.detection.validators import dry_run_detection

    fields._clear_agg_field_cache()
    grid = _GridProbe({"ssh.authentication.success"})
    draft = _sigma_draft("event.dataset:zeek.ssh AND ssh.authentication.success:true")
    out = await dry_run_detection(draft, elastic=grid, settings=settings_kratos)  # type: ignore[arg-type]
    assert out.schema_ok is True
    assert out.validator_note is None


# --- the console filter gives the answer that the query tool gives ----------


def _console_must(settings: Settings, oql: str) -> list[dict[str, Any]]:
    from soc_ai.webui.alerts_query import build_filter

    built = build_filter(settings, time_range="24h", severity=None, oql=oql)
    return built["bool"]["must"]  # type: ignore[no-any-return]


def test_the_console_filter_widens_a_name_as_the_query_tool_does(
    settings_kratos: Settings,
) -> None:
    settings_kratos.webui_alerts_query = "tags:alert"
    must = _console_must(settings_kratos, "zeek.ssh.auth_success:true")
    for name in fields.SSH_AUTH_SUCCESS:
        assert {name: "true"} in _terms(must[-1])


def test_the_configured_alert_source_is_not_widened(settings_kratos: Settings) -> None:
    """Negative control: the operator wrote the source query. It runs as written."""
    settings_kratos.webui_alerts_query = "tags:alert"
    settings_kratos.webui_extra_detections = False
    must = _console_must(settings_kratos, "source.ip:192.0.2.7")
    assert must[0] == {"term": {"tags": "alert"}}


# --- a note never suggests a field that the validator refuses ----------------


def _grouped_then_check(agg: str, counts: dict[str, int]) -> list[dict[str, Any]]:
    grouped = {
        "took": 1,
        "hits": {"total": {"value": 40}, "hits": []},
        "aggregations": {agg: {"buckets": []}},
    }
    check = {
        "took": 1,
        "hits": {"hits": []},
        "aggregations": {
            "field_check": {"buckets": {key: {"doc_count": n} for key, n in counts.items()}}
        },
    }
    return [grouped, check]


async def _groupby_note(settings: Settings, oql: str, responses: list[dict[str, Any]]) -> str:
    fake_es = AsyncMock()
    fake_es.search.side_effect = responses
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        elastic = ElasticClient(settings)
    result = await query_events_oql(oql, elastic=elastic, settings=settings)
    return result.field_note or ""


@pytest.mark.asyncio
async def test_a_note_does_not_suggest_a_field_that_the_validator_refuses(
    settings_kratos: Settings,
) -> None:
    """The note said "Run the groupby on `ntlm.hostname`", and the validator refuses that field."""
    note = await _groupby_note(
        settings_kratos,
        "event.dataset:zeek.ntlm | groupby zeek.ntlm.hostname",
        _grouped_then_check("by_zeek_ntlm_hostname", {"scope": 40, "f0_0": 40, "f0_1": 0}),
    )
    assert "`zeek.ntlm.hostname`" in note
    assert "ntlm.hostname`." not in note.replace("`zeek.ntlm.hostname`", "")
    assert "Run the groupby on" not in note
    assert "t_describe_dataset" in note


@pytest.mark.asyncio
async def test_a_note_still_suggests_a_field_that_the_validator_accepts(
    settings_kratos: Settings,
) -> None:
    """Negative control."""
    note = await _groupby_note(
        settings_kratos,
        "event.dataset:zeek.ssh | groupby zeek.ssh.auth_success",
        _grouped_then_check(
            "by_zeek_ssh_auth_success", {"scope": 40, "f0_0": 40, "f0_1": 0, "f0_2": 0}
        ),
    )
    assert "Run the groupby on `ssh.authentication.success`." in note
