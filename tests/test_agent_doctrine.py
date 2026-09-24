"""The catalog reaches triage: which raw alert documents a flagged spec claims.

The matcher is soc_ai/hunting/match.py, evaluated against the alert's own
``_source``. Security Onion's Sigma pipeline nests the original event under an
``event_data`` envelope, so the document is tried both as-is and one level down.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest
from soc_ai.agent import doctrine

_GUID = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"


def _dcsync_event(user: str = "localuser") -> dict[str, Any]:
    """A 4662 exercising a replication right, as Windows writes it."""
    return {
        "event": {"code": "4662"},
        "winlog": {
            "event_data": {
                "Properties": f"%%7688 {{{_GUID}}}",
                "SubjectUserName": user,
            }
        },
    }


def _sigma_envelope(event: dict[str, Any]) -> dict[str, Any]:
    """The same event as a Security Onion Sigma alert carries it: nested."""
    return {
        "rule": {"name": "Active Directory Replication from Non Machine Account"},
        "tags": ["alert"],
        "event_data": event,
    }


def test_a_flat_dcsync_document_matches_the_dcsync_spec() -> None:
    spec = doctrine.spec_declaring_no_baseline_for(_dcsync_event())
    assert spec is not None
    assert spec.id == "identity-4662-dcsync-nonmachine"


def test_a_sigma_envelope_is_read_one_level_down() -> None:
    """The alert queue had to learn this the hard way: every Sigma detection
    arrived with no addresses because the reader looked only at the top level."""
    spec = doctrine.spec_declaring_no_baseline_for(_sigma_envelope(_dcsync_event()))
    assert spec is not None
    assert spec.id == "identity-4662-dcsync-nonmachine"


def test_a_machine_account_replicating_is_not_claimed() -> None:
    """NEGATIVE CONTROL. The spec's own ``none`` clause: a domain controller
    replicating under its machine account is the normal case, and the gate must
    not refuse a benign verdict on it."""
    assert doctrine.spec_declaring_no_baseline_for(_dcsync_event(user="SR-DC01$")) is None


def test_a_4662_without_a_replication_right_is_not_claimed() -> None:
    """NEGATIVE CONTROL. The predicate is the spec's, not 'any 4662'."""
    doc = _dcsync_event()
    doc["winlog"]["event_data"]["Properties"] = "%%7688 {some-other-guid}"
    assert doctrine.spec_declaring_no_baseline_for(doc) is None


def test_a_spec_without_the_flag_never_claims_a_document() -> None:
    """NEGATIVE CONTROL. Kerberoast matches its document and is NOT flagged, so a
    volume argument may still clear it; the matcher must not hand it over."""
    rc4 = {
        "event": {"code": "4769"},
        "winlog": {"event_data": {"TicketEncryptionType": "0x17", "ServiceName": "svc_sql"}},
    }
    assert doctrine.spec_declaring_no_baseline_for(rc4) is None


@pytest.mark.parametrize("raw", [None, {}, "not a dict", {"event_data": "not a dict"}])
def test_an_unreadable_document_claims_nothing(raw: Any) -> None:
    assert doctrine.spec_declaring_no_baseline_for(raw) is None


def test_a_catalog_that_cannot_load_claims_nothing() -> None:
    """Fail OPEN. A gate that raises takes the investigation with it, and a
    broken catalog is a catalog problem, not a reason to lose a verdict."""
    doctrine.no_baseline_specs.cache_clear()
    with patch("soc_ai.agent.doctrine.load_catalog", side_effect=ValueError("bad yaml")):
        assert doctrine.spec_declaring_no_baseline_for(_dcsync_event()) is None
    doctrine.no_baseline_specs.cache_clear()
