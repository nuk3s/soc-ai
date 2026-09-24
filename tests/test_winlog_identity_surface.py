"""The Windows Security fields the identity detections turn on, end to end.

Credential abuse is the case that motivated proactive hunting: on the live range
a DCSync + Kerberoast + AS-REP chain ran to completion and produced no alert an
analyst would ever see. Every field that separates those attacks from their
benign baseline lives under ``winlog.event_data``, and until this change none of
them was queryable.

Two halves, deliberately landed together because each is unsafe without the
other. The query half admits the fields; the egress half decides, for each one,
whether its value is an organisational identifier that must be tokenised or a
public Windows schema constant that must survive.

The second half is the one worth testing hardest. Masking is the safe default and
it is nearly always right, but for the AD control-access-right GUID it is
actively harmful: that GUID IS the DCSync detection, so an Oracle handed
``<redacted:unclassified>`` there is asked to second-guess a verdict while blind
to the only field the verdict rests on.
"""

from __future__ import annotations

import pytest
from soc_ai.oracle.backstop import mask_unclassified_scalars
from soc_ai.oracle.redact import Mapping, sanitize_case
from soc_ai.oracle.sanitize import desanitize
from soc_ai.so_client.oql import FieldWhitelist, get_whitelist

# The three AD control-access rights the DCSync spec matches, any one of which
# is the detection on its own. Public, published by Microsoft, byte-identical
# in every Active Directory forest on earth.
DS_REPLICATION_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
DS_REPLICATION_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
DS_REPLICATION_GET_CHANGES_IN_FILTERED_SET = "89e95b76-444d-4c62-991a-0facbeda640c"
REPLICATION_RIGHTS = (
    DS_REPLICATION_GET_CHANGES,
    DS_REPLICATION_GET_CHANGES_ALL,
    DS_REPLICATION_GET_CHANGES_IN_FILTERED_SET,
)

SUFFIXES = (".lan", ".local")


def _through_the_boundary(case: dict) -> tuple[dict, Mapping, int]:
    """sanitize -> backstop, the real order used on the wire."""
    mapping = Mapping()
    sanitized = sanitize_case(case, mapping)
    masked, n = mask_unclassified_scalars(sanitized, suffixes=SUFFIXES)
    return masked, mapping, n


# ---------------------------------------------------------------------------
# The query half
# ---------------------------------------------------------------------------


def test_the_discriminating_fields_are_queryable() -> None:
    """Each of these is the single clause that separates an attack from its baseline.

    Measured on the range on 2026-09-04, with the DCSync clause then matching
    only the DS-Replication-Get-Changes GUID: 38 documents carried that right,
    36 of them the DC's own machine account. Excluding machine accounts by
    ``SubjectUserName`` took it to 2, at 100% precision. That one clause was
    unexpressible before this change. The spec has since widened to three
    rights and has not been re-counted.
    """
    wl = get_whitelist()
    for field in (
        "winlog.event_data.Properties",  # DCSync: the replication right
        "winlog.event_data.SubjectUserName",  # DCSync: exclude machine accounts
        "winlog.event_data.TicketEncryptionType",  # Kerberoast: RC4 among AES
        "winlog.event_data.ServiceName",  # Kerberoast: which SPN
        "winlog.event_data.PreAuthType",  # AS-REP: pre-auth disabled
        "winlog.channel",
    ):
        assert wl.is_allowed(field), f"{field} is not queryable"


# The authentication package is the field the range's own operating
# documentation names for separating management traffic from real users, and a
# hunt asking whether an authentication was Kerberos or NTLM failed four
# queries with unknown-or-forbidden-field errors. Counted on the range over
# fourteen days, all from system.security:
#
#   AuthenticationPackageName   Negotiate 20614, Kerberos 19984, NTLM 526
#   LogonProcessName            Kerberos 19984, Advapi 19395, NtLmSsp 526, ...
#   LmPackageName               NTLM V2 501, NTLM V1 24
#   winlog.logon.type           Network 37452, Service 2271, Interactive 1320
#
# Every one of them is populated. The last is the readable alias for the
# numeric ``LogonType`` that was already admitted, which is the one an analyst
# writes and the one a hunt spec reads back.
AUTHENTICATION_PACKAGE_FIELDS = (
    "winlog.event_data.AuthenticationPackageName",
    "winlog.event_data.LogonProcessName",
    "winlog.event_data.LmPackageName",
    "winlog.logon.type",
)


@pytest.mark.parametrize("field", AUTHENTICATION_PACKAGE_FIELDS)
def test_the_authentication_package_is_queryable(field: str) -> None:
    """Kerberos or NTLM is the first question Windows triage asks.

    A bare zero on it is not a finding, it is a field that was never asked, and
    a model reads the difference as innocence.
    """
    assert get_whitelist().is_allowed(field), f"{field} is not queryable"


def test_winlog_is_enumerated_not_prefixed() -> None:
    """A ``winlog`` prefix would admit several hundred leaves in one line.

    Many of them carry identifiers no redaction route classifies, which is the
    same open-set problem the allow-known-safe backstop exists to close,
    reintroduced on the query side. Narrow by construction, and this test is what
    keeps it narrow: adding the prefix later would silently undo the reasoning.
    """
    wl = get_whitelist()
    assert "winlog" not in wl.prefixes
    assert not wl.is_allowed("winlog.event_data.SomeLeafNobodyClassified")
    assert not wl.is_allowed("winlog")


def test_the_whitelist_file_still_parses_into_a_real_policy() -> None:
    """Guard against a malformed edit quietly producing an allow-nothing policy."""
    wl = FieldWhitelist.from_file()
    assert len(wl.prefixes) > 50
    assert len(wl.exact) > 20
    assert wl.is_allowed("source.ip")
    assert not wl.is_allowed("_index")


# ---------------------------------------------------------------------------
# The egress half
# ---------------------------------------------------------------------------


def test_every_organisational_identifier_is_tokenised() -> None:
    """Realm, account, SPN and workstation must not reach the model verbatim."""
    case = {
        "winlog": {
            "event_data": {
                "SubjectDomainName": "RANGE.LAB",
                "TargetDomainName": "RANGE",
                "SubjectUserName": "localuser",
                "ServiceName": "svc_sql",
                "WorkstationName": "SR-WS01",
            }
        }
    }
    out, _, _ = _through_the_boundary(case)
    ed = out["winlog"]["event_data"]

    for raw in ("RANGE.LAB", "RANGE", "localuser", "svc_sql", "SR-WS01"):
        assert raw not in str(ed), f"{raw!r} egressed verbatim"
    for key in ed:
        assert ed[key] != "<redacted:unclassified>", (
            f"{key} fell through to the backstop instead of being classified; "
            "an opaque mask cannot be correlated or desanitised"
        )


def test_the_service_principal_name_is_an_account_not_a_mask() -> None:
    """An SPN is an account name, so it tokenises rather than being masked.

    Left unclassified it reached the backstop and came back opaque, which is safe
    but loses Kerberoast attribution completely: the Oracle could see that RC4 was
    requested and never which account requested it.
    """
    out, _, _ = _through_the_boundary({"winlog": {"event_data": {"ServiceName": "svc_sql"}}})
    assert out["winlog"]["event_data"]["ServiceName"].startswith("USER_")


@pytest.mark.parametrize("right", REPLICATION_RIGHTS)
def test_the_ad_schema_guids_survive_to_the_oracle(right: str) -> None:
    """The GUID IS the detection. Masking it makes the adjudication impossible.

    These are public Microsoft schema constants, identical in every forest, and
    they carry no organisational information at all.

    Parametrised over each replication right ALONE, because that is how the DC
    writes them: one document per right checked. The backstop admits
    ``Properties`` by field path, not by enumerating GUID values, so widening
    the spec needed no allowlist change. This is the test that would notice if
    that ever became a value list with one entry.
    """
    case = {
        "winlog": {
            "channel": "Security",
            "event_data": {
                "Properties": f"%%7688 {{{right}}}",
                "ObjectType": "%%2211 {19195a5b-6da0-11d0-afd3-00c04fd930c9}",
                "AccessMask": "0x100",
                "TicketEncryptionType": "0x17",
                "PreAuthType": "0",
            },
        }
    }
    out, _, masked = _through_the_boundary(case)
    ed = out["winlog"]["event_data"]

    assert right in ed["Properties"], f"replication right {right} was masked"
    assert "19195a5b" in ed["ObjectType"]
    assert ed["AccessMask"] == "0x100"
    assert ed["TicketEncryptionType"] == "0x17"
    assert ed["PreAuthType"] == "0"
    assert masked == 0


def test_the_authentication_package_survives_to_the_oracle() -> None:
    """Every value here is a public Windows constant, not an organisational name.

    "Kerberos", "NTLM", "NtLmSsp", "NTLM V2", "Network" are the same strings on
    every Windows host on earth. They are also word-shaped, which is what makes
    this test necessary: the backstop masks an unclassified word-shaped scalar,
    so admitting these fields to the query surface without classifying them for
    egress would let the Oracle adjudicate a Kerberos-versus-NTLM finding with
    the package itself redacted.
    """
    case = {
        "winlog": {
            "logon": {"type": "Network"},
            "event_data": {
                "AuthenticationPackageName": "NTLM",
                "LogonProcessName": "NtLmSsp ",
                "LmPackageName": "NTLM V2",
                "LogonType": "3",
            },
        }
    }
    out, _, masked = _through_the_boundary(case)
    ed = out["winlog"]["event_data"]

    assert ed["AuthenticationPackageName"] == "NTLM"
    assert ed["LogonProcessName"] == "NtLmSsp "
    assert ed["LmPackageName"] == "NTLM V2"
    assert ed["LogonType"] == "3"
    assert out["winlog"]["logon"]["type"] == "Network"
    assert masked == 0


def test_an_unclassified_winlog_leaf_is_still_masked() -> None:
    """Negative control. The allowlist must be an allowlist, not a bypass.

    Without this the previous test could pass because the backstop stopped
    working on winlog paths generally, rather than because these specific fields
    were classified.
    """
    out, _, masked = _through_the_boundary(
        {"winlog": {"event_data": {"SomeLeafNobodyClassified": "PDC01"}}}
    )
    assert out["winlog"]["event_data"]["SomeLeafNobodyClassified"] == ("<redacted:unclassified>")
    assert masked == 1


def test_the_tokens_desanitise_back() -> None:
    """A label the Oracle cites has to resolve to the real value on the way back.

    This is why the winlog realm route mints HOST rather than reviving the dead
    ``DOMAIN`` label kind: both the backstop's shape check and this module's
    desanitiser enumerate only USER/HOST/IP/MAC/EMAIL, so a ``DOMAIN_01`` token
    would be masked outbound and would not resolve inbound.
    """
    case = {
        "winlog": {"event_data": {"SubjectDomainName": "RANGE.LAB", "SubjectUserName": "localuser"}}
    }
    out, mapping, _ = _through_the_boundary(case)
    ed = out["winlog"]["event_data"]

    restored = desanitize(
        f"{ed['SubjectUserName']} authenticated to {ed['SubjectDomainName']}", mapping
    )
    assert restored == "localuser authenticated to RANGE.LAB"


def test_a_realm_does_not_rewrite_a_public_domain_that_starts_with_it() -> None:
    """A regression this branch introduced, and the reason it mattered.

    An AD realm is a dictionary word by nature — CORP, RANGE, LAB, HOME — and
    Pass 2's alternation boundary does not reject a leading dot or hyphen. With
    the realm harvested and propagating, a realm of ``CORP`` rewrote the
    attacker's own ``corp-cdn.evil.com`` to ``HOST_01-cdn.evil.com``, presenting
    a public command-and-control domain to the Oracle as an internal asset. It
    did so consistently across the narrative and the evidence, so the Oracle had
    no way to notice, and ``desanitize`` restored it on the way back, so neither
    did the operator.

    Leaving the leaf unclassified was strictly SAFER than classifying it wrong:
    the backstop would have masked it in place and corrupted nothing.
    """
    case = {
        "winlog": {"event_data": {"SubjectDomainName": "CORP"}},
        "local_summary": "The DC beaconed to corp-cdn.evil.com every 60s.",
        "dns": {"question": {"name": "corp.evil.com"}},
    }
    mapping = Mapping()
    out = sanitize_case(case, mapping)

    assert out["winlog"]["event_data"]["SubjectDomainName"].startswith("HOST_")
    assert out["local_summary"] == case["local_summary"], (
        "the realm rewrote a substring of a public domain in free text"
    )
    assert out["dns"]["question"]["name"] == "corp.evil.com", (
        "the realm rewrote a public FQDN in the evidence"
    )


def test_a_realm_still_round_trips_from_its_own_field() -> None:
    """No-propagate must not cost the round trip; ``direct_replace`` covers it."""
    mapping = Mapping()
    out = sanitize_case({"winlog": {"event_data": {"TargetDomainName": "RANGE"}}}, mapping)
    label = out["winlog"]["event_data"]["TargetDomainName"]
    assert label.startswith("HOST_")
    assert desanitize(label, mapping) == "RANGE"


def test_a_short_realm_is_covered_too() -> None:
    """The pre-existing carve-out was <=3 chars; a realm needs it at any length."""
    for realm in ("LAB", "RANGE", "CONTOSO"):
        mapping = Mapping()
        out = sanitize_case(
            {
                "winlog": {"event_data": {"SubjectDomainName": realm}},
                "local_summary": f"traffic to {realm.lower()}-cdn.example.com",
            },
            mapping,
        )
        assert out["local_summary"] == f"traffic to {realm.lower()}-cdn.example.com", (
            f"realm {realm!r} corrupted a public domain"
        )
