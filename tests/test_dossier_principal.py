"""Tests for principal canonicalisation (soc_ai.dossier.principal)."""

from __future__ import annotations

import pytest
from soc_ai.dossier.principal import (
    PrincipalKind,
    canonical_principal,
    is_machine_account,
    principal_kind,
)


@pytest.mark.parametrize(
    "spelling",
    [
        "RANGE\\alice",
        "range\\alice",
        "alice@corp.example",
        "ALICE@RANGE.LAB",
        "alice",
        "ALICE",
        "  alice  ",
    ],
)
def test_every_spelling_of_one_user_collapses_to_one_key(spelling: str) -> None:
    assert canonical_principal(spelling) == "alice"


def test_domain_is_dropped_not_kept_so_two_planes_agree() -> None:
    # system.security says RANGE\alice; zeek.kerberos says alice@corp.example.
    # If the domain survived, these would be two entities and the binding
    # between a host and its user would never form.
    assert canonical_principal("RANGE\\alice") == canonical_principal("alice@corp.example")


def test_machine_accounts_are_identified_and_keep_their_dollar() -> None:
    assert is_machine_account("SR-WS01$") is True
    assert canonical_principal("RANGE\\SR-WS01$") == "sr-ws01$"
    assert principal_kind("SR-WS01$") is PrincipalKind.MACHINE


def test_a_sid_is_kept_verbatim_and_uppercased() -> None:
    # A SID is already canonical and case-insensitive; lowercasing it would
    # make it unreadable next to Windows' own rendering.
    assert canonical_principal("s-1-5-21-1004336348-1177238915-682003330-512") == (
        "S-1-5-21-1004336348-1177238915-682003330-512"
    )
    assert principal_kind("S-1-5-18") is PrincipalKind.SID


def test_well_known_local_accounts_are_not_global_identities() -> None:
    # SYSTEM on one host is not SYSTEM on another. Treating them as one
    # principal would bind every host in the estate to a single entity.
    assert principal_kind("SYSTEM") is PrincipalKind.LOCAL
    assert principal_kind("NT AUTHORITY\\SYSTEM") is PrincipalKind.LOCAL


def test_empty_and_placeholder_principals_are_rejected() -> None:
    for junk in ["", "   ", "-", "N/A", "null", None]:
        assert canonical_principal(junk) is None


def test_a_machine_account_is_not_mistaken_for_a_local_account() -> None:
    # Both are "not a person", but a machine account is a global identity with
    # a real profile and SYSTEM is not. Collapsing them loses the DC's own
    # machine identity, which several priors read.
    assert principal_kind("RANGE\\SR-DC01$") is PrincipalKind.MACHINE
    assert principal_kind("NT AUTHORITY\\SYSTEM") is PrincipalKind.LOCAL


def test_an_upn_with_a_dotted_account_survives_the_split() -> None:
    # first.last@corp.example must not lose its dot to the domain splitter.
    assert canonical_principal("first.last@corp.example") == "first.last"
